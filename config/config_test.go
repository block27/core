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

	assert.Equal(t, test, "test")
	assert.Equal(t, development, "development")
	assert.Equal(t, production, "production")

	assert.Equal(t, serialNumber, "serial_number")
	assert.Equal(t, serialNumberVar, "SERIAL_NUMBER")
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
