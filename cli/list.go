package cli

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/service/iam"
	jmespath "github.com/jmespath/go-jmespath"
	"gopkg.in/alecthomas/kingpin.v2"
)

// ListConfig stores the parameters needed for a List command
type ListConfig struct {
	ClientID string
	Claim    string
}

// ConfigureList configures the list command with arguments and flags
func ConfigureList(app *kingpin.Application, config *GlobalConfig) {

	listConfig := ListConfig{}

	cmd := app.Command("list", "List roles that a ClientID can assume")

	cmd.Flag("client_id", "The OpenID Connect Client ID").
		Required().
		StringVar(&listConfig.ClientID)

	cmd.Flag("claim", "The claim used in the IAM policies, prrovider:claim").
		Required().
		StringVar(&listConfig.Claim)

	cmd.Action(func(c *kingpin.ParseContext) error {
		ListCommand(app, config, &listConfig)
		return nil
	})
}

// ListCommand retrieves the list of AWS roles that have trust policues that accept a given client_id
func ListCommand(app *kingpin.Application, config *GlobalConfig, listConfig *ListConfig) {

	svc := iam.New(config.Session)

	input := &iam.ListRolesInput{}
	listRoleResult, err := svc.ListRoles(input)
	app.FatalIfError(err, "Unable to list roles")

	for _, role := range listRoleResult.Roles {

		decodedValue, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
		app.FatalIfError(err, "Unable to urldecode document")

		var d interface{}
		err = json.Unmarshal([]byte(decodedValue), &d)
		app.FatalIfError(err, "Unable to unmarshall AssumeRolePolicyDocument")

		query := fmt.Sprintf("contains(Statement[].Condition.StringEquals.\"%s\", '%s')", listConfig.Claim, listConfig.ClientID)
		containsClientID, err := jmespath.Search(query, d)
		app.FatalIfError(err, "Unable to parse AssumeRolePolicyDocument")
		if containsClientID.(bool) {
			fmt.Println(*role.RoleName)
			fmt.Println(*role.Arn)
		}
	}
}
