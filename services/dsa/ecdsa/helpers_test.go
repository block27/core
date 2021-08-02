package ecdsa

import (
	"fmt"
	"os"
	"testing"

	"github.com/block27/core/config"
	"github.com/block27/core/helpers"

	"github.com/stretchr/testify/assert"
)

// AssertStructCorrectness ...
func AssertStructCorrectness(t *testing.T, k KeyAPI, o string, c string) {
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

	assert.Equal(t, "active", k.Struct().Status)
	assert.Equal(t, fmt.Sprintf("ecdsa.%s <==> %s", o, c), k.Struct().KeyType)
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

func ClearSingleTestKey(t *testing.T, p string) {
	t.Helper()

	err := os.RemoveAll(p)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("successfully removed [%s]", p)
}

// CheckFullKeyFileObjects checks that a full private, public pem and object
// files are created when a new key is created
func CheckFullKeyFileObjects(t *testing.T, c config.Reader, k KeyAPI, f string) {
	t.Helper()

	// Check for filesystem keys are present
	checkKeyFileObjects(t, f,
		fmt.Sprintf("%s/ecdsa/%s", c.GetString("paths.keys"), k.FilePointer()))
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
