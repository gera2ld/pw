package config

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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

func expandHome(path, homeDir string) string {
	if path == "" || path[0] != '~' {
		return path
	}
	if len(path) == 1 {
		return homeDir
	}
	if path[1] == '/' || path[1] == filepath.Separator {
		return filepath.Join(homeDir, path[2:])
	}
	rest := ""
	name := path[1:]
	if i := strings.IndexRune(path, filepath.Separator); i >= 0 {
		name = path[1:i]
		rest = path[i+1:]
	}
	u, err := user.Lookup(name)
	if err != nil {
		return path
	}
	return filepath.Join(u.HomeDir, rest)
}

func NewConfig() *ConfigType {
	usr, _ := user.Current()
	homeDir := usr.HomeDir

	rootDir := expandHome(os.Getenv("PW_ROOT"), homeDir)
	if rootDir == "" {
		rootDir = filepath.Join(homeDir, ".config", "pw")
	}
	identities := expandHome(os.Getenv("PW_IDENTITIES"), homeDir)
	if identities == "" {
		identities = filepath.Join(rootDir, "identities")
	}
	dataDir := expandHome(os.Getenv("PW_DATA_DIR"), homeDir)
	if dataDir == "" {
		dataDir = "vault"
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(rootDir, dataDir)
	}
	debug := os.Getenv("PW_DEBUG") == "true"
	if debug {
		log.Printf("rootDir: %s", rootDir)
		log.Printf("identities: %s", identities)
		log.Printf("dataDir: %s", dataDir)
	}
	return &ConfigType{
		RootDir:    rootDir,
		Identities: identities,
		DataDir:    dataDir,
		EnvSuffix:  ".age",
		IndexFile:  filepath.Join(dataDir, "index.dat.age"),
		ConfigFile: ".pw.yml",
		Debug:      debug,
	}
}
