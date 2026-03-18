package config

import (
	"errors"
	"log"
	"pw/internal/filehandler"

	"gopkg.in/yaml.v3"
)

type UserConfigData struct {
	Recipients []string `yaml:"recipients"`
}

type UserConfigType struct {
	config      *ConfigType
	filehandler *filehandler.FileHandler
	Data        UserConfigData
}

func NewUserConfig(config *ConfigType, filehandler *filehandler.FileHandler) *UserConfigType {
	userConfig := &UserConfigType{
		config:      config,
		filehandler: filehandler,
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
