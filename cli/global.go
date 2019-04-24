package cli

import (
	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// GlobalConfig used for defaults and command line arguments
type GlobalConfig struct {
	//Region in AWS used by KMSAuth and BLESS
	Region       string
	Profile      string
	AuthProvider []AuthConfig

	Session *session.Session
	Keyring *keyring.Keyring
}

// ConfigureGlobal application arguments and flags
func ConfigureGlobal(app *kingpin.Application, config *GlobalConfig) {

	app.Flag("region", "The region in AWS").
		Default(config.Region).
		Envar("AWS_REGION").
		StringVar(&config.Region)

	app.Flag("profile", "The profile to use as defined in the AWS config file").
		Default(config.Profile).
		Envar("AWS_PROFILE").
		StringVar(&config.Profile)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {

		// Attempt to open the aws-vault keychain
		keychain, err := keyring.Open(keyring.Config{
			KeychainName:             "aws-oidc",
			ServiceName:              "aws-oidc",
			AllowedBackends:          []keyring.BackendType{keyring.KeychainBackend},
			KeychainTrustApplication: true,
		})
		kingpin.FatalIfError(err, "Could not open aws-vault keychain")
		config.Keyring = &keychain

		config.Session = session.Must(session.NewSessionWithOptions(session.Options{
			Config:            aws.Config{Region: aws.String(config.Region)},
			Profile:           config.Profile,
			SharedConfigState: session.SharedConfigEnable,
		}))

		return nil
	})

}
