package cli

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sts"
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

	svcSTS := sts.New(session.New())
	inputSTS := &sts.AssumeRoleWithWebIdentityInput{
		DurationSeconds:  aws.Int64(execConfig.Duration),
		RoleArn:          aws.String("arn:aws:iam::892845094662:role/onelogin-test-oidc"),
		RoleSessionName:  aws.String(authResult.Token.Subject),
		WebIdentityToken: aws.String(authResult.JWT),
	}

	assumeRoleResult, err := svcSTS.AssumeRoleWithWebIdentity(inputSTS)
	app.FatalIfError(err, "Unable to assume role: %v", err)

	svcLambda := lambda.New(session.New(&aws.Config{
		Credentials: credentials.NewStaticCredentials(
			*assumeRoleResult.Credentials.AccessKeyId,
			*assumeRoleResult.Credentials.SecretAccessKey,
			*assumeRoleResult.Credentials.SessionToken,
		),
		Region: aws.String("us-west-2"),
	}))

	lambdaPayload := LambdaPayload{
		Token: authResult.JWT,
		Role:  execConfig.RoleArn,
	}
	lambdaPayloadJSON, err := json.Marshal(&lambdaPayload)
	if err != nil {
		app.Fatalf("Error creating lambda payload json")
	}

	inputLambda := &lambda.InvokeInput{
		FunctionName:   aws.String("identity-broker"),
		InvocationType: aws.String("RequestResponse"),
		Payload:        lambdaPayloadJSON,
	}
	result, err := svcLambda.Invoke(inputLambda)
	if err != nil {
		app.Fatalf("Error invoking Lambda: " + err.Error())
	}
	if *result.FunctionError != "" {
		app.Fatalf("Remote error: " + string(result.Payload))
	}

	awsCreds := AwsCredentialHelperData{}
	if err := json.Unmarshal(result.Payload, &awsCreds); err != nil {
		app.Fatalf("Error decoding credential json")
	}
	output, err := json.Marshal(awsCreds)
	if err != nil {
		app.Fatalf("Error encoding credential json")
	}
	fmt.Println(string(output))
}
