package cli

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentity"
	"github.com/stoggi/aws-oidc/provider"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
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
	AgentCommant []string
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
		StringsVar(&execConfig.AgentCommant)

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
		AgentCommand: execConfig.AgentCommant,
	}

	authResult, err := provider.Authenticate(providerConfig)
	app.FatalIfError(err, "Error authenticating to identity provider: %v", err)

	svc := cognitoidentity.New(session.New(&aws.Config{
		Region: aws.String("ap-southeast-2"),
	}))
	inputGetID := &cognitoidentity.GetIdInput{
		AccountId:      aws.String("811702477007"),
		IdentityPoolId: aws.String("ap-southeast-2:b0a04ab4-9989-4ee0-b9f7-9b1e56fe0f19"),
		Logins: map[string]*string{
			"cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_XloydykNV": aws.String(authResult.JWT),
		},
	}
	getIDResult, err := svc.GetId(inputGetID)
	app.FatalIfError(err, "Unable to get ID: %v", err)

	inputGetCredentials := &cognitoidentity.GetCredentialsForIdentityInput{
		IdentityId: getIDResult.IdentityId,
		Logins: map[string]*string{
			"cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_XloydykNV": aws.String(authResult.JWT),
		},
	}
	credentialsResult, err := svc.GetCredentialsForIdentity(inputGetCredentials)
	app.FatalIfError(err, "Unable to get credentials: %v", err)

	expiry := *credentialsResult.Credentials.Expiration
	credentialData := AwsCredentialHelperData{
		Version:         1,
		AccessKeyID:     *credentialsResult.Credentials.AccessKeyId,
		SecretAccessKey: *credentialsResult.Credentials.SecretKey,
		SessionToken:    *credentialsResult.Credentials.SessionToken,
		Expiration:      expiry.Format("2006-01-02T15:04:05Z"),
	}

	output, err := json.Marshal(credentialData)
	if err != nil {
		app.Fatalf("Error encoding credential json")
	}
	fmt.Println(string(output))
}
