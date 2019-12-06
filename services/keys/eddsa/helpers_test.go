package eddsa

import (
	"fmt"
	"testing"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/helpers"
	"github.com/stretchr/testify/assert"
)

// AssertStructCorrectness ...
func AssertStructCorrectness(t *testing.T, k KeyAPI) {
	t.Helper()

	assert.NotNil(t, k.Struct().GID)
	assert.NotNil(t, k.Struct().Name)
	assert.NotNil(t, k.Struct().Slug)
	assert.NotNil(t, k.Struct().FingerprintMD5)
	assert.NotNil(t, k.Struct().FingerprintSHA)

	assert.NotNil(t, k.Struct().PrivatePemPath)
	assert.NotNil(t, k.Struct().PrivateKeyB64)
	assert.NotNil(t, k.Struct().PublicKeyB64)
	assert.NotNil(t, k.Struct().PrivateKeyPath)
	assert.NotNil(t, k.Struct().PublicKeyPath)

	assert.Equal(t, k.Struct().Status, "active")
	assert.Equal(t, k.Struct().KeyType, "eddsa.PrivateKey <==> ed25519")
}

// AssertStructNilness ...
func AssertStructNilness(t *testing.T, k KeyAPI) {
	t.Helper()

	assert.Equal(t, k.Struct().GID.String(), "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, k.Struct().Name, "")
	assert.Equal(t, k.Struct().Slug, "")
	assert.Equal(t, k.Struct().Status, "")
	assert.Equal(t, k.Struct().KeyType, "")
	assert.Equal(t, k.Struct().FingerprintMD5, "")
	assert.Equal(t, k.Struct().FingerprintSHA, "")

	assert.Equal(t, k.Struct().PrivatePemPath, "")
	assert.Equal(t, k.Struct().PrivateKeyB64, "")
	assert.Equal(t, k.Struct().PublicKeyB64, "")
	assert.Equal(t, k.Struct().PrivateKeyPath, "")
	assert.Equal(t, k.Struct().PublicKeyPath, "")
}

func CheckFullKeyFileObjects(t *testing.T, c config.Reader, k KeyAPI, f string) {
	t.Helper()

	// Check for filesystem keys are present
	checkKeyFileObjects(t, f,
		fmt.Sprintf("%s/%s", c.GetString("paths.keys"), k.FilePointer()))
}

func checkKeyFileObjects(t *testing.T, f string, p string) {
	paths := []string{
		fmt.Sprintf("%s/%s", p, "obj.bin"),
		fmt.Sprintf("%s/%s", p, "public.key"),
		fmt.Sprintf("%s/%s", p, "private.key"),
		fmt.Sprintf("%s/%s", p, "private.pem"),
	}

	for _, p := range paths {
		if !helpers.FileExists(p) {
			t.Fatalf("%s failed to writeToFS() -> %s", f, p)
		}
	}
}
