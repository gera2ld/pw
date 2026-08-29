package config

import (
	"errors"
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

func (c *UserConfigType) SaveUserConfig() error {
	data, err := yaml.Marshal(c.Data)
	if err != nil {
		return err
	}
	return c.filehandler.WriteFile(c.config.ConfigFile, string(data))
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
			result.Recipients = *raw.Recipients
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
	c.cache[relDir] = result
	return result
}

func (c *UserConfigType) GetRecipientsForPath(relDir string) []string {
	return c.mergedConfig(relDir).Recipients
}

func (c *UserConfigType) GetObscureNamesForPath(relDir string) bool {
	return c.mergedConfig(relDir).ObscureNames
}

func (c *UserConfigType) AddRecipient(publicKey string) error {
	for _, recipient := range c.Data.Recipients {
		if recipient == publicKey {
			return errors.New("recipient already exists")
		}
	}

	c.Data.Recipients = append(c.Data.Recipients, publicKey)
	return c.SaveUserConfig()
}

func (c *UserConfigType) RemoveRecipient(publicKey string) error {
	newRecipients := []string{}
	for _, recipient := range c.Data.Recipients {
		if recipient != publicKey {
			newRecipients = append(newRecipients, recipient)
		}
	}
	c.Data.Recipients = newRecipients
	return c.SaveUserConfig()
}
