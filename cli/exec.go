package cli

import (
	"encoding/json"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/stoggi/aws-oidc/provider"

	"gopkg.in/alecthomas/kingpin.v2"
)

type ExecConfig struct {
	RoleArn      string
	Duration     int64
	ProviderURL  string
	ClientID     string
	ClientSecret string
	PKCE         bool
	Nonce        bool
	ReAuth       bool
	AgentCommand []string
}

// json metadata for AWS credential process. Ref: https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type AwsCredentialHelperData struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration,omitempty"`
}

type LambdaPayload struct {
	Role  string `json:"role"`
	Token string `json:"token"`
}

func ConfigureExec(app *kingpin.Application, config *GlobalConfig) {

	execConfig := ExecConfig{}

	cmd := app.Command("exec", "Execute a command with temporary AWS credentials")

	cmd.Default()

	cmd.Flag("role_arn", "The AWS role you want to assume").
		Required().
		StringVar(&execConfig.RoleArn)

	cmd.Flag("duration", "The duration to assume the role for in seconds").
		Default("3600").
		Int64Var(&execConfig.Duration)

	cmd.Flag("provider_url", "The OpenID Connect Provider URL").
		Required().
		StringVar(&execConfig.ProviderURL)

	cmd.Flag("client_id", "The OpenID Connect Client ID").
		Required().
		StringVar(&execConfig.ClientID)

	cmd.Flag("client_secret", "The OpenID Connect Client Secret").
		Default("").
		StringVar(&execConfig.ClientSecret)

	cmd.Flag("pkce", "Use PKCE in the OIDC code flow").
		Default("true").
		BoolVar(&execConfig.PKCE)

	cmd.Flag("nonce", "Require a nonce included and verified in the token").
		Default("true").
		BoolVar(&execConfig.Nonce)

	cmd.Flag("reauth", "Require reauthentication by the identity provider").
		Default("false").
		BoolVar(&execConfig.ReAuth)

	cmd.Arg("agent", "The executable and arguments of the local browser to use").
		Default("open", "{}").
		StringsVar(&execConfig.AgentCommand)

	cmd.Action(func(c *kingpin.ParseContext) error {
		ExecCommand(app, config, &execConfig)
		return nil
	})
}

func ExecCommand(app *kingpin.Application, config *GlobalConfig, execConfig *ExecConfig) {

	providerConfig := &provider.ProviderConfig{
		ClientID:     execConfig.ClientID,
		ClientSecret: execConfig.ClientSecret,
		ProviderURL:  execConfig.ProviderURL,
		PKCE:         execConfig.PKCE,
		Nonce:        execConfig.Nonce,
		ReAuth:       execConfig.ReAuth,
		AgentCommand: execConfig.AgentCommand,
	}

	item, err := (*config.Keyring).Get(execConfig.ClientID)

	if err != keyring.ErrKeyNotFound {
		oauth2Token := provider.Oauth2Token{}
		err := json.Unmarshal(item.Data, &oauth2Token)
		// Maybe fail silently in case oauth2 lib is not backward compatible
		app.FatalIfError(err, "Error parsing Oauth2 token from token : %v", err)

		accessKeyJson, err := assumeRoleWithWebIdentity(execConfig, &oauth2Token)
		if err == nil {
			fmt.Println(accessKeyJson)
			return
		}
	}

	oauth2Token, err := provider.Authenticate(providerConfig)

	accessKeyJson, err := assumeRoleWithWebIdentity(execConfig, oauth2Token)
	app.FatalIfError(err, "Error assume role with web identity : %v", err)

	json, err := json.Marshal(&oauth2Token)
	app.FatalIfError(err, "Can't serialize Oauth2 token : %v", err)

	(*config.Keyring).Set(keyring.Item{
		Key:	execConfig.ClientID,
		Data:	json,
		Label: fmt.Sprintf("Oauth2 token for %s",execConfig.RoleArn),
		Description:"OIDC JWT",
	})
	fmt.Printf(accessKeyJson)
}


func assumeRoleWithWebIdentity(execConfig *ExecConfig, oauth2Token *provider.Oauth2Token) (string, error) {

	svc := sts.New(session.New())

	input := &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  aws.Int64(execConfig.Duration),
		RoleArn:          aws.String(execConfig.RoleArn),
		RoleSessionName:  aws.String("aws-oidc"),
		WebIdentityToken: aws.String(oauth2Token.IDToken),
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

	json, err := json.Marshal(&credentialData)
	if err != nil {
		return "", err
	}

	return string(json), nil
}