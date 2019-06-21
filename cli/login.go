package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
)

// LoginConfig stores the parameters needed for an login command
type LoginConfig struct {
	Profile string
}

type signinSession struct {
	SessionID    string `json:"sessionId"`
	SessionKey   string `json:"sessionKey"`
	SessionToken string `json:"sessionToken"`
}

type signinToken struct {
	SigninToken string
}

// ConfigureLogin configures the login command with arguments and flags
func ConfigureLogin(app *kingpin.Application, config *GlobalConfig) {

	loginConfig := LoginConfig{}

	cmd := app.Command("login", "Login to the AWS console for a given profile")

	cmd.Arg("profile", "Name of the profile").
		StringVar(&config.Profile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		LoginCommand(app, config, &loginConfig)
		return nil
	})
}

// LoginCommand exchanges temporary credentials for an AWS Console signin url
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func LoginCommand(app *kingpin.Application, config *GlobalConfig, loginConfig *LoginConfig) {

	// Retrieve credentials from current session. This will try and get credentials
	// using aws-oidc itself if configured in ~/.aws/config.
	val, err := config.Session.Config.Credentials.Get()
	if err != nil {
		app.Fatalf("Unable to get credentials for profile: %s", config.Profile)
	}

	credentialData := signinSession{
		SessionID:    val.AccessKeyID,
		SessionKey:   val.SecretAccessKey,
		SessionToken: val.SessionToken,
	}
	credentialJSON, err := json.Marshal(&credentialData)
	if err != nil {
		app.Fatalf("Unable to marshal credentials for profile: %s", config.Profile)
	}

	// Create the federation URL to exchange access keys for a session token
	tokenURL, _ := url.Parse("https://signin.aws.amazon.com/federation")
	tokenQuery := url.Values{}
	tokenQuery.Set("Action", "getSigninToken")
	tokenQuery.Set("Session", string(credentialJSON))
	tokenURL.RawQuery = tokenQuery.Encode()

	var client = &http.Client{
		Timeout: time.Second * 60,
	}
	resp, err := client.Get(tokenURL.String())
	if err != nil {
		app.Fatalf("Unable to get signin token for profile: %s", config.Profile)
	} else if resp.StatusCode != 200 {
		app.Fatalf("GetSigninToken returned %d instead of 200 for profile: %s", resp.StatusCode, config.Profile)
	}
	defer resp.Body.Close()

	token := signinToken{}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		app.Fatalf("Unable to decode GetSigninToken response for profile: %s", config.Profile)
	}

	// Create the federation URL to exchange the session token for a login URL
	loginURL, _ := url.Parse("https://signin.aws.amazon.com/federation")
	loginQuery := url.Values{}
	loginQuery.Set("Action", "login")
	loginQuery.Set("Destination", "https://console.aws.amazon.com/")
	loginQuery.Set("SigninToken", token.SigninToken)
	loginURL.RawQuery = loginQuery.Encode()

	fmt.Println(loginURL)
}
