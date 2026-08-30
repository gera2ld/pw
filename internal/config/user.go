package config

import (
	"log"
	"path/filepath"
	"pw/internal/filehandler"
	"strings"

	"gopkg.in/yaml.v3"
)

type UserConfigData struct {
	Recipients   []string `yaml:"recipients"`
	ObscureNames bool     `yaml:"obscure_names"`
}

type UserConfigType struct {
	config      *ConfigType
	filehandler *filehandler.FileHandler
	Data        UserConfigData
	cache       map[string]UserConfigData
}

func NewUserConfig(config *ConfigType, filehandler *filehandler.FileHandler) *UserConfigType {
	userConfig := &UserConfigType{
		config:      config,
		filehandler: filehandler,
		cache:       make(map[string]UserConfigData),
	}
	err := userConfig.LoadUserConfig()
	if config.Debug {
		if err != nil {
			log.Printf("Error loading user config: %v\n", err)
		} else {
			log.Printf("User config: %+v\n", userConfig.Data)
		}
	}
	return userConfig
}

func (c *UserConfigType) LoadUserConfig() error {
	data, err := c.filehandler.ReadFile(c.config.ConfigFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal([]byte(data), &c.Data)
}

type rawConfig struct {
	Recipients   *[]string `yaml:"recipients"`
	ObscureNames *bool     `yaml:"obscure_names"`
}

func (c *UserConfigType) mergedConfig(relDir string) UserConfigData {
	if cached, ok := c.cache[relDir]; ok {
		return cached
	}
	var result UserConfigData
	apply := func(raw rawConfig) {
		if raw.Recipients != nil {
			result.Recipients = append(result.Recipients, *raw.Recipients...)
		}
		if raw.ObscureNames != nil {
			result.ObscureNames = *raw.ObscureNames
		}
	}
	// Global
	if data, err := c.filehandler.ReadFile(c.config.ConfigFile); err == nil {
		var raw rawConfig
		if err := yaml.Unmarshal([]byte(data), &raw); err == nil {
			apply(raw)
		}
	}
	// Vault-root
	cfgPath := filepath.Join(c.config.DataDir, c.config.ConfigFile)
	if data, err := c.filehandler.ReadFile(cfgPath); err == nil {
		var raw rawConfig
		if err := yaml.Unmarshal([]byte(data), &raw); err == nil {
			apply(raw)
		}
	}
	// Ancestors: vault/a/.pw.yml, vault/a/b/.pw.yml, ...
	dir := "."
	for _, part := range strings.Split(relDir, "/") {
		if part == "" || part == "." {
			continue
		}
		dir = filepath.Join(dir, part)
		cfgPath := filepath.Join(c.config.DataDir, dir, c.config.ConfigFile)
		if data, err := c.filehandler.ReadFile(cfgPath); err == nil {
			var raw rawConfig
			if err := yaml.Unmarshal([]byte(data), &raw); err == nil {
				apply(raw)
			}
		}
	}
	// Dedupe recipients (union of all levels) while preserving first-seen order.
	seen := make(map[string]struct{}, len(result.Recipients))
	deduped := result.Recipients[:0]
	for _, r := range result.Recipients {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		deduped = append(deduped, r)
	}
	result.Recipients = deduped

	c.cache[relDir] = result
	return result
}

func (c *UserConfigType) GetRecipientsForPath(relDir string) []string {
	return c.mergedConfig(relDir).Recipients
}

func (c *UserConfigType) GetObscureNamesForPath(relDir string) bool {
	return c.mergedConfig(relDir).ObscureNames
}
