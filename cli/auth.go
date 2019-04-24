package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stoggi/aws-oidc/provider"

	"gopkg.in/alecthomas/kingpin.v2"
)

// AuthConfig defines a single OpenIDConnect provider
type AuthConfig struct {
	// The name of the provider when definied in the TOML configuration file
	Name string `toml:"name"`

	// RoleARN the role in AWS that should be assumed with the identity token
	RoleArn string `toml:"role_arn"`

	// Duration in seconds that the temporary AWS credentials should last for
	// Between 900 (15 minutes) and 43200 (12 hours)
	Duration int64 `toml:"duration"`

	// ProviderURL the endpoint that defines the OIDC provider.
	// Should serve https://[ProviderURL]/.well-known/openid-configuration
	ProviderURL string `toml:"provider_url"`

	// ClientID configured with your OIDC provider
	ClientID string `toml:"client_id"`

	// ClientSecret should only be specified if your OIDC provider requires it.
	// Normally with PKCE you don't require a client_secret.
	ClientSecret string `toml:"client_secret"`

	// DisablePKCE removes the code_challenge and code_verifier parameters of a
	// proof key for code exchange OAuth flow. Only disbale this if your identity
	// provider does not support PKCE.
	DisablePKCE bool `toml:"disable_pkce"`

	// DisableNonce removes a random nonce sent to the server, and added to the token
	// This nonce is verified when the token is received by the command line app.
	DisableNonce bool `toml:"disable_nonce"`

	// AgentCommand contains the command and arguments that open a browser. The URL
	// to be opened will be appended, or use a parameter of {} to substitute the URL.
	AgentCommand []string `toml:"agent"`
}

// AwsCredentialHelperData for AWS credential process
// https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type AwsCredentialHelperData struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration,omitempty"`
}

func configureFlags(cmd *kingpin.CmdClause, authConfig *AuthConfig) {

	cmd.Flag("role_arn", "The AWS role you want to assume").
		Default(authConfig.RoleArn).
		StringVar(&authConfig.RoleArn)

	cmd.Flag("duration", "The duration to assume the role for in seconds").
		Default(strconv.FormatInt(max(authConfig.Duration, 900), 10)).
		Int64Var(&authConfig.Duration)

	cmd.Flag("provider_url", "The OpenID Connect Provider URL").
		Default(authConfig.ProviderURL).
		StringVar(&authConfig.ProviderURL)

	cmd.Flag("client_id", "The OpenID Connect Client ID").
		Default(authConfig.ClientID).
		StringVar(&authConfig.ClientID)

	cmd.Flag("client_secret", "The OpenID Connect Client Secret").
		StringVar(&authConfig.ClientSecret)

	cmd.Flag("disable_pkce", "Disable the use of PKCE in the OIDC code flow").
		BoolVar(&authConfig.DisablePKCE)

	cmd.Flag("disable_nonce", "Disable the use of a nonce included and verified in the token").
		BoolVar(&authConfig.DisableNonce)

	cmd.Flag("agent", "The executable and arguments of the local browser to use").
		StringsVar(&authConfig.AgentCommand)
}

// ConfigureAuth configures the auth command with arguments and flags
func ConfigureAuth(app *kingpin.Application, config *GlobalConfig) {

	cmd := app.Command("auth", "Authenticate to the identity provider, and assume a role in AWS")

	providers := append(config.AuthProvider, AuthConfig{Name: "default"})

	for _, a := range providers {
		authConfig := a

		pcmd := cmd.Command(authConfig.Name, "Authenticate using the named profile in the config file")
		configureFlags(pcmd, &authConfig)

		pcmd.Action(func(c *kingpin.ParseContext) error {
			if authConfig.ClientID == "" {
				return fmt.Errorf("Missing ClientID for provider %s", authConfig.Name)
			}
			if _, err := url.ParseRequestURI(authConfig.ProviderURL); err != nil {
				return fmt.Errorf("Missing ProviderURL, or invalid format for provider %s", authConfig.Name)
			}
			if len(authConfig.AgentCommand) == 0 {
				return fmt.Errorf("Missing Agent command for provider %s", authConfig.Name)
			}
			if _, err := arn.Parse(authConfig.RoleArn); err != nil {
				return fmt.Errorf("Missing RoleArn, or invalid format for provider %s", authConfig.Name)
			}

			AuthCommand(app, config, &authConfig)
			return nil
		})

		if authConfig.Name == "default" {
			pcmd.Default()
		}
	}
}

// AuthCommand executes the authentication with the selected OpenIDConnect provider
func AuthCommand(app *kingpin.Application, config *GlobalConfig, authConfig *AuthConfig) {

	p := &provider.ProviderConfig{
		ClientID:     authConfig.ClientID,
		ClientSecret: authConfig.ClientSecret,
		ProviderURL:  authConfig.ProviderURL,
		PKCE:         !authConfig.DisablePKCE,
		Nonce:        !authConfig.DisableNonce,
		AgentCommand: authConfig.AgentCommand,
	}
	oauth2Token := provider.OAuth2Token{}

	item, err := (*config.Keyring).Get(authConfig.ClientID)
	if err != keyring.ErrKeyNotFound {
		if err := json.Unmarshal(item.Data, &oauth2Token); err != nil {
			// Log this error only, because we can attempt to recover by getting a new token
			app.Errorf("Unable to unmarshal OAuth2Token from keychain: %v", err)
		}
	}

	err = p.Authenticate(&oauth2Token)
	app.FatalIfError(err, "Error authenticating with identity provider")

	AWSCredentialsJSON, err := assumeRoleWithWebIdentity(authConfig, oauth2Token.IDToken)
	app.FatalIfError(err, "Error assume role with web identity")

	json, err := json.Marshal(&oauth2Token)
	app.FatalIfError(err, "Error marshalling OAuth2 token")
	err = (*config.Keyring).Set(keyring.Item{
		Key:         authConfig.ClientID,
		Data:        json,
		Label:       fmt.Sprintf("OAuth2 token for %s", authConfig.RoleArn),
		Description: "OIDC OAuth2 Token",
	})
	app.FatalIfError(err, "Error storing OAuth2 Token in keychain")

	fmt.Printf(AWSCredentialsJSON)
}

func assumeRoleWithWebIdentity(authConfig *AuthConfig, idToken string) (string, error) {

	svc := sts.New(session.New())

	input := &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  aws.Int64(authConfig.Duration),
		RoleArn:          aws.String(authConfig.RoleArn),
		RoleSessionName:  aws.String("aws-oidc"),
		WebIdentityToken: aws.String(idToken),
	}

	assumeRoleResult, err := svc.AssumeRoleWithWebIdentity(input)
	if err != nil {
		return "", err
	}

	expiry := *assumeRoleResult.Credentials.Expiration
	credentialData := AwsCredentialHelperData{
		Version:         1,
		AccessKeyID:     *assumeRoleResult.Credentials.AccessKeyId,
		SecretAccessKey: *assumeRoleResult.Credentials.SecretAccessKey,
		SessionToken:    *assumeRoleResult.Credentials.SessionToken,
		Expiration:      expiry.Format("2006-01-02T15:04:05Z"),
	}

	credentialJSON, err := json.Marshal(&credentialData)
	if err != nil {
		return "", err
	}
	return string(credentialJSON), nil
}

func max(x, y int64) int64 {
	if x > y {
		return x
	}
	return y
}
