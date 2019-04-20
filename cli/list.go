package cli

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	jmespath "github.com/jmespath/go-jmespath"
	"gopkg.in/alecthomas/kingpin.v2"
)

type ListConfig struct {
	ClientID string
}

func ConfigureList(app *kingpin.Application, config *GlobalConfig) {

	listConfig := ListConfig{}

	cmd := app.Command("list", "List roles that a ClientID can assume")

	cmd.Flag("client_id", "The OpenID Connect Client ID").
		Required().
		StringVar(&listConfig.ClientID)

	cmd.Action(func(c *kingpin.ParseContext) error {
		ListCommand(app, config, &listConfig)
		return nil
	})
}

func ListCommand(app *kingpin.Application, config *GlobalConfig, listConfig *ListConfig) {

	svc := iam.New(session.New())

	input := &iam.ListRolesInput{}
	listRoleResult, err := svc.ListRoles(input)
	app.FatalIfError(err, "Unable to list roles")

	for _, role := range listRoleResult.Roles {

		decodedValue, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
		app.FatalIfError(err, "Unable to urldecode document")

		var d interface{}
		err = json.Unmarshal([]byte(decodedValue), &d)
		app.FatalIfError(err, "Unable to unmarshall AssumeRolePolicyDocument")
		v, err := jmespath.Search("contains(Statement[].Condition.StringEquals.\"openid-connect.onelogin.com/oidc:aud\", `abc`)", d)
		app.FatalIfError(err, "Unable to parse AssumeRolePolicyDocument")

		fmt.Println(v)
	}
}
