package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	Env  = "env"

	Environment    = "environment"
	EnvironmentVar = "ENVIRONMENT"

	Development = "development"
	Production  = "production"

	SerialNumberVar = "SERIAL_NUMBER"
	SerialNumber 		= "serial_number"
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
	Defaults(config)
}

// Defaults is the default settings functor
func Defaults(config ConfigReader) {
	config.SetDefault(Environment, GetEnv(EnvironmentVar, Development))
	config.SetDefault(SerialNumber, GetEnv(SerialNumberVar, "0x0000000001"))
}

// GetEnv - pull values or set defaults.
func GetEnv(key, fallback string) string {
	value := os.Getenv(key)

	if len(value) == 0 {
		return fallback
	}

	return value
}

// LoadConfig - returns configuration for a particular app
func LoadConfig(defaultSetup DefaultSettings) (ConfigReader, error) {
	config := viper.New()

	Defaults(config)

	return config, nil
}

func LoadLogger(config ConfigReader) *logrus.Logger {
	log := logrus.New()
	env := config.GetString(Environment)

	if env == Production {
		log.Formatter = &logrus.JSONFormatter{}
	} else {
		log.Formatter = &logrus.TextFormatter{}
	}

	log.Out = os.Stdout

	log.SetLevel(logrus.InfoLevel)

	return log
}
