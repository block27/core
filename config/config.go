package config

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

const (
	env = "env"

	environment    = "environment"
	environmentVar = "ENVIRONMENT"

	serialNumber    = "serial_number"
	serialNumberVar = "SERIAL_NUMBER"

	development = "development"
	production  = "production"
	test        = "test"

	configurationFrmt = "yaml"
	configurationFile = "config"

	homePath = "/var/data"
	testPath = "/tmp/data"
)

var (
	hostKeysPath string

	HostMasterKeyPath string
	HostMasterIvPath  string
	HostSerialPath    string

	HostPin1 string
	HostPin2 string

	ExtBase1Path string
	ExtBase2Path string
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
	WriteConfig() error
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

	config.SetDefault("created_at", t)
	config.SetDefault("updated_at", t)

	basePath := homePath
	if config.GetString(environment) == test {
		basePath = testPath
	}

	// Set all variables here to ensure test paths are properly configured
	hostKeysPath = fmt.Sprintf("%s/keys", basePath)

	HostMasterKeyPath = fmt.Sprintf("%s/key", basePath)
	HostMasterIvPath = fmt.Sprintf("%s/iv", basePath)
	HostSerialPath = fmt.Sprintf("%s/serial", basePath)

	HostPin1 = fmt.Sprintf("%s/pin1", basePath)
	HostPin2 = fmt.Sprintf("%s/pin2", basePath)

	ExtBase1Path = "var/data/pin"
	ExtBase2Path = "var/data/pin"

	config.SetDefault("paths.base", basePath)
	config.SetDefault("paths.keys", hostKeysPath)
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

	basePath := config.GetString("paths.base")

	// Check for config file
	cFile := fmt.Sprintf("%s/%s.%s", basePath, configurationFile, configurationFrmt)
	if _, err := os.Stat(cFile); os.IsNotExist(err) {
		os.Create(cFile)
	}

	// Create key path
	if _, err := os.Stat(hostKeysPath); os.IsNotExist(err) {
		os.MkdirAll(hostKeysPath, os.ModePerm)
	}

	// Toml config file settings
	config.SetConfigType(configurationFrmt)
	config.SetConfigName(configurationFile)
	config.AddConfigPath(basePath)

	if err := config.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fatal error config file: %s", err)
	}

	config.AutomaticEnv()

	// Write them to yaml config
	config.WriteConfig()

	return config, nil
}

// LoadLogger - set the defaults for the logging class
func LoadLogger(config ConfigReader) *logrus.Logger {
	log := logrus.New()

	log.Formatter = new(prefixed.TextFormatter)

	log.Out = os.Stdout

	log.SetLevel(logrus.DebugLevel)

	return log
}
