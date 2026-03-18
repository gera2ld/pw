package main

import (
	"fmt"
	"os"
	"pw/internal/cli"
	"pw/internal/config"
	"pw/internal/filehandler"
	"pw/internal/secrets"
)

var version string
var builtAt string

func main() {
	globalConfig := config.NewConfig()
	filehandler := filehandler.NewFileHandler(globalConfig.RootDir, globalConfig.Debug)
	userConfig := config.NewUserConfig(globalConfig, filehandler)
	sm := secrets.NewSecretManager(globalConfig, userConfig, filehandler)
	rootCmd := cli.NewRootCommand(version, builtAt, sm)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
