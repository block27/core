package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var Config Reader

func init() {
	os.Setenv("ENVIRONMENT", "test")
	Config, _ = LoadConfig(Defaults)
	os.Setenv("ENVIRONMENT", "")

	if Config.GetString("environment") != "test" {
		panic(fmt.Errorf("test [environment] is not in [test] mode"))
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, env, "env")
	assert.Equal(t, environment, "environment")
	assert.Equal(t, environmentVar, "ENVIRONMENT")

	assert.Equal(t, serialNumber, "serial_number")
	assert.Equal(t, serialNumberVar, "SERIAL_NUMBER")

	assert.Equal(t, development, "development")
	assert.Equal(t, production, "production")
	assert.Equal(t, test, "test")

	assert.Equal(t, configurationFrmt, "yaml")
	assert.Equal(t, configurationFile, "config")

	assert.Equal(t, homePath, "/var/data")
	assert.Equal(t, testPath, "/tmp/data")

	assert.Equal(t, Config.GetString("paths.base"), "/tmp/data")
	assert.Equal(t, hostKeysPath, "/tmp/data/keys")

	assert.Equal(t, HostMasterKeyPath, "/tmp/data/key")
	assert.Equal(t, HostMasterIvPath, "/tmp/data/iv")
	assert.Equal(t, HostSerialPath, "/tmp/data/serial")

	assert.Equal(t, HostPin1, "/tmp/data/pin1")
	assert.Equal(t, HostPin2, "/tmp/data/pin2")

	assert.Equal(t, ExtBase1Path, "var/data/pin")
	assert.Equal(t, ExtBase2Path, "var/data/pin")
}

func TestLoadLogger(t *testing.T) {
	logger := LoadLogger(Config)

	if assert.NotNil(t, logger) {
		assert.Equal(t, logger.Formatter, &prefixed.TextFormatter{})
		assert.Equal(t, logger.Level, logrus.DebugLevel)
	}
}

func TestGetEnvExists(t *testing.T) {
	os.Setenv("FOO", "nothing")

	assert.Equal(t, getEnv("FOO", "invalid"), "nothing")

	os.Unsetenv("FOO")
}

func TestGetEnvNotExists(t *testing.T) {
	os.Setenv("FOO", "")

	assert.Equal(t, getEnv("FOO", "invalid"), "invalid")

	os.Unsetenv("FOO")
}
