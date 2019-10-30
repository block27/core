package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var Config ConfigReader

func init() {
	os.Setenv("ENVIRONMENT", "test")
	Config, _ = LoadConfig(ConfigDefaults)
	os.Setenv("ENVIRONMENT", "")
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

	assert.Equal(t, createdAt, "created_at")
	assert.Equal(t, updatedAt, "updated_at")


	assert.Equal(t, HostMasterKeyPath, "/var/data/key")
	assert.Equal(t, HostMasterIvPath, "/var/data/iv")
	assert.Equal(t, HostSerialPath, "/var/data/serial")

	assert.Equal(t, hostKeyPath, "/var/data/keys")

	assert.Equal(t, HostPin1, "/var/data/pin1")
	assert.Equal(t, HostPin2, "/var/data/pin2")

	assert.Equal(t, ExtBase1Path, "var/data/pin")
	assert.Equal(t, ExtBase2Path, "var/data/pin")

	assert.Equal(t, configurationFrmt, "yaml")
	assert.Equal(t, configurationFile, "config")
	assert.Equal(t, configurationPath, "/var/data")
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
