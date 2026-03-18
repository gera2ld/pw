package config

import (
	"log"
	"os"
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
	rootDir := os.Getenv("PW_ROOT")
	if rootDir == "" {
		rootDir = "."
	}
	identities := os.Getenv("PW_IDENTITIES")
	if identities == "" {
		identities = "./identities"
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
