package config

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
)

type ConfigType struct {
	RootDir    string
	Identities string
	DataDir    string
	EnvSuffix  string
	IndexFile  string
	ConfigFile string
	Debug      bool
}

func NewConfig() *ConfigType {
	usr, _ := user.Current()
	homeDir := usr.HomeDir

	rootDir := os.Getenv("PW_ROOT")
	if rootDir == "" {
		rootDir = filepath.Join(homeDir, ".config", "pw")
	}
	identities := os.Getenv("PW_IDENTITIES")
	if identities == "" {
		identities = filepath.Join(rootDir, "identities")
	}
	debug := os.Getenv("PW_DEBUG") == "true"
	if debug {
		log.Printf("rootDir: %s", rootDir)
		log.Printf("identities: %s", identities)
	}
	return &ConfigType{
		RootDir:    rootDir,
		Identities: identities,
		DataDir:    "vault",
		EnvSuffix:  ".age",
		IndexFile:  "vault/index.dat.age",
		ConfigFile: "config.yml",
		Debug:      debug,
	}
}
