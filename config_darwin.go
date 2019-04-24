package main

import (
	"os"
	"os/user"
	"path/filepath"
)

func homeDir() string {
	if currentUser, err := user.Current(); err == nil {
		return currentUser.HomeDir
	}
	return ""
}

func execDir() string {
	if currentExecutable, err := os.Executable(); err == nil {
		return filepath.Dir(currentExecutable)
	}
	return ""
}

// GetConfigFilePath returns the path of the configuration file
func GetConfigFilePath() string {
	return filepath.Join(homeDir(), ".aws-oidc/config")
}

// GetLogPath returns the path that should be used to store logs
func GetLogPath() string {
	return filepath.Join(homeDir(), "Library/Logs/aws-oidc.log")
}
