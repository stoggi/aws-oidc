package main

import (
	"io"
	"log"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/stoggi/aws-oidc/cli"
	"gopkg.in/alecthomas/kingpin.v2"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	run(os.Args[1:], os.Exit)
}

func run(args []string, exit func(int)) {

	f, err := os.OpenFile(GetLogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	wrt := io.MultiWriter(os.Stderr, f)
	log.SetOutput(wrt)

	// Default configuration, values are overridden by command line options.
	config := cli.GlobalConfig{}
	if _, err := toml.DecodeFile(GetConfigFilePath(), &config); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Error decoding TOML: %v\n", err)
		}
	}

	app := kingpin.New(
		"aws-oidc",
		"Assume roles in AWS using an OIDC identity provider",
	)

	app.Version(Version)
	app.Terminate(exit)
	app.UsageWriter(os.Stdout)
	app.ErrorWriter(wrt)

	cli.ConfigureGlobal(app, &config)
	cli.ConfigureAuth(app, &config)
	cli.ConfigureExec(app, &config)
	cli.ConfigureList(app, &config)

	kingpin.MustParse(app.Parse(args))
}
