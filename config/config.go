package config

import (
	"fmt"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	env  = "env"

	environment    = "environment"
	environmentVar = "ENVIRONMENT"

	serialNumber 		= "serial_number"
	serialNumberVar = "SERIAL_NUMBER"

	development = "development"
	production  = "production"
	test				= "test"

	createdAt 	= "created_at"
	updatedAt 	= "updated_at"

	// Runtime specific
	HostMasterKeyPath 	= "/var/data/key"
	HostMasterIvPath 		= "/var/data/iv"
	HostSerialPath 			= "/var/data/serial"

	HostPin1						= "/var/data/pin1"
	HostPin2 						= "/var/data/pin2"

	ExtBase1Path   			= "var/data/pin"
	ExtBase2Path   			= "var/data/pin"

	configurationFrmt		= "yaml"
	configurationFile 	= "config"
	configurationPath 	= "/var/data"
)

// ConfigReader represents configuration reader
type ConfigReader interface {
	Get(string) interface{}
	GetString(string) string
	GetInt(string) int
	GetBool(string) bool
	GetStringMap(string) map[string]interface{}
	GetStringMapString(string) map[string]string
	GetStringSlice(string) []string
	SetDefault(string, interface{})
}

// DefaultSettings is the function for configuring defaults
type DefaultSettings func(config ConfigReader)

// ConfigDefaults - returns the defauls of the config passed
func ConfigDefaults(config ConfigReader) {
	defaults(config)
}

// Defaults is the default settings functor
func defaults(config ConfigReader) {
	config.SetDefault(environment, getEnv(environmentVar, development))
	config.SetDefault(serialNumber, getEnv(serialNumberVar, "0x0000000001"))

	t := getTimeStamp()

	config.SetDefault(createdAt, t)
	config.SetDefault(updatedAt, t)
	config.SetDefault("base.name", "sigma")
}

// GetEnv - pull values or set defaults.
func getEnv(key, fallback string) string {
	value := os.Getenv(key)

	if len(value) == 0 {
		return fallback
	}

	return value
}

func getTimeStamp() string {
	return time.Now().Format(time.RFC850)
}


// LoadConfig - returns configuration for a particular app
func LoadConfig(defaultSetup DefaultSettings) (ConfigReader, error) {
	config := viper.New()

	// Set base ENV defaults
	defaults(config)

	if config.GetString(environment) != test {
		// Check for config file
		cFile := fmt.Sprintf("%s/%s.%s", configurationPath, configurationFile, configurationFrmt)
		if _, err := os.Stat(cFile); os.IsNotExist(err) {
			os.Create(cFile)
		}

		// Toml config file settings
		config.SetConfigType(configurationFrmt)
		config.SetConfigName(configurationFile)
		config.AddConfigPath(configurationPath)

		err := config.ReadInConfig()
		if err !=nil {
			return nil, fmt.Errorf("fatal error config file: %s", err)
		}

		// Write them to yaml config
		config.WriteConfig()
	}

	return config, nil
}

// LoadLogger - set the defaults for the logging class
func LoadLogger(config ConfigReader) *logrus.Logger {
	log := logrus.New()
	env := config.GetString(environment)

	if env == production {
		log.Formatter = &logrus.JSONFormatter{}
	} else {
		log.Formatter = &logrus.TextFormatter{}
	}

	log.Out = os.Stdout

	log.SetLevel(logrus.InfoLevel)

	return log
}
