package cli

import (
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"gopkg.in/alecthomas/kingpin.v2"
)

// ExecConfig stores the parameters needed for an exec command
type ExecConfig struct {
	Profile string
	Command string
	Args    []string
	Signals chan os.Signal
}

// ConfigureExec configures the exec command with arguments and flags
func ConfigureExec(app *kingpin.Application, config *GlobalConfig) {

	execConfig := ExecConfig{}

	cmd := app.Command("exec", "Retrieve temporary credentials and set them as environment variables")

	cmd.Arg("profile", "Name of the profile").
		StringVar(&config.Profile)

	cmd.Arg("cmd", "Command to execute").
		Default(os.Getenv("SHELL")).
		StringVar(&execConfig.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&execConfig.Args)

	cmd.Action(func(c *kingpin.ParseContext) error {
		execConfig.Signals = make(chan os.Signal)
		ExecCommand(app, config, &execConfig)
		return nil
	})
}

// ExecCommand retrieves temporary credentials and sets them as environment variables
func ExecCommand(app *kingpin.Application, config *GlobalConfig, execConfig *ExecConfig) {

	if os.Getenv("AWS_OIDC") != "" {
		app.Fatalf("aws-vault sessions should be nested with care, unset $AWS_OIDC to force")
		return
	}

	val, err := config.Session.Config.Credentials.Get()
	if err != nil {
		app.Fatalf("Unable to get credentials for profile: %s", config.Profile)
	}

	env := environ(os.Environ())
	env.Set("AWS_OIDC", config.Profile)

	env.Unset("AWS_ACCESS_KEY_ID")
	env.Unset("AWS_SECRET_ACCESS_KEY")
	env.Unset("AWS_CREDENTIAL_FILE")
	env.Unset("AWS_DEFAULT_PROFILE")
	env.Unset("AWS_PROFILE")

	if config.Region != "" {
		log.Printf("Setting subprocess env: AWS_DEFAULT_REGION=%s, AWS_REGION=%s", config.Region, config.Region)
		env.Set("AWS_DEFAULT_REGION", config.Region)
		env.Set("AWS_REGION", config.Region)
	}

	log.Println("Setting subprocess env: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	env.Set("AWS_ACCESS_KEY_ID", val.AccessKeyID)
	env.Set("AWS_SECRET_ACCESS_KEY", val.SecretAccessKey)

	if val.SessionToken != "" {
		log.Println("Setting subprocess env: AWS_SESSION_TOKEN, AWS_SECURITY_TOKEN")
		env.Set("AWS_SESSION_TOKEN", val.SessionToken)
		env.Set("AWS_SECURITY_TOKEN", val.SessionToken)
	}

	cmd := exec.Command(execConfig.Command, execConfig.Args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	signal.Notify(execConfig.Signals, os.Interrupt, os.Kill)

	if err := cmd.Start(); err != nil {
		app.Fatalf("%v", err)
	}
	// wait for the command to finish
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	for {
		select {
		case sig := <-execConfig.Signals:
			if err = cmd.Process.Signal(sig); err != nil {
				app.Errorf("%v", err)
				break
			}
		case err := <-waitCh:
			var waitStatus syscall.WaitStatus
			if exitError, ok := err.(*exec.ExitError); ok {
				waitStatus = exitError.Sys().(syscall.WaitStatus)
				os.Exit(waitStatus.ExitStatus())
			}
			if err != nil {
				app.Fatalf("%v", err)
			}
			return
		}
	}
}

// environ is a slice of strings representing the environment, in the form "key=value".
type environ []string

// Unset an environment variable by key
func (e *environ) Unset(key string) {
	for i := range *e {
		if strings.HasPrefix((*e)[i], key+"=") {
			(*e)[i] = (*e)[len(*e)-1]
			*e = (*e)[:len(*e)-1]
			break
		}
	}
}

// Set adds an environment variable, replacing any existing ones of the same key
func (e *environ) Set(key, val string) {
	e.Unset(key)
	*e = append(*e, key+"="+val)
}
