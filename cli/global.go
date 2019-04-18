package cli

import (
	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

// GlobalConfig used for defaults and command line arguments
type GlobalConfig struct {
	//Region in AWS used by KMSAuth and BLESS
	Region string

	AwsConfig *vault.Config
	Keyring   *keyring.Keyring
}

// ConfigureGlobal application arguments and flags
func ConfigureGlobal(app *kingpin.Application, config *GlobalConfig) {

	app.Flag("region", "The region in AWS").
		Default("ap-southeast-2").
		StringVar(&config.Region)

	app.PreAction(func(c *kingpin.ParseContext) (err error) {

		// Attempt to open the aws-vault keychain
		keychain, err := keyring.Open(keyring.Config{
			KeychainName:    "aws-oidc",
			ServiceName:     "aws-oidc",
			AllowedBackends: []keyring.BackendType{keyring.KeychainBackend},
			KeychainTrustApplication: true,
		})
		kingpin.FatalIfError(err, "Could not open aws-vault keychain")

		//config.AwsConfig = awsConfig
		config.Keyring = &keychain

		return nil
	})

}
