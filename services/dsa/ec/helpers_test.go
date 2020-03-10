package ec

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/amanelis/core-zero/config"
	"github.com/amanelis/core-zero/helpers"
	"github.com/amanelis/core-zero/services/dsa"

	"github.com/stretchr/testify/assert"
)

// AssertStructCorrectness ...
func AssertStructCorrectness(t *testing.T, k KeyAPI, o string, c string) {
	t.Helper()

	assert.NotNil(t, k.GetAttributes().GID)
	assert.NotNil(t, k.GetAttributes().Name)
	assert.NotNil(t, k.GetAttributes().Slug)
	assert.NotNil(t, k.GetAttributes().FingerprintMD5)
	assert.NotNil(t, k.GetAttributes().FingerprintSHA)

	if strings.Contains(k.GetAttributes().KeyType, dsa.Private) {
		assert.NotNil(t, k.Struct().privateKeyPEM)
		assert.Equal(t, dsa.ToString(c, o), k.GetAttributes().KeyType)
	}

	assert.NotNil(t, k.Struct().publicKeyPEM)

	assert.Equal(t, "active", k.GetAttributes().Status)

}

// AssertStructNilness ...
func AssertStructNilness(t *testing.T, k KeyAPI) {
	t.Helper()

	assert.Equal(t, k.GetAttributes().GID.String(), "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, k.GetAttributes().Name, "")
	assert.Equal(t, k.GetAttributes().Slug, "")
	assert.Equal(t, k.GetAttributes().Status, "")
	assert.Equal(t, k.GetAttributes().KeyType, "")
	assert.Equal(t, k.GetAttributes().FingerprintMD5, "")
	assert.Equal(t, k.GetAttributes().FingerprintSHA, "")

	assert.Equal(t, k.Struct().privateKeyPEM, "")
	assert.Equal(t, k.Struct().publicKeyPEM, "")
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
		fmt.Sprintf("%s/ec/%s", c.GetString("paths.keys"), k.GetAttributes().FilePointer()))
}

func checkKeyFileObjects(t *testing.T, f string, p string) {
	paths := []string{
		fmt.Sprintf("%s/%s", p, "obj.bin"),
		fmt.Sprintf("%s/%s", p, "key.pem"),
		fmt.Sprintf("%s/%s", p, "pub.pem"),
	}

	for _, p := range paths {
		if !helpers.FileExists(p) {
			t.Fatalf("%s failed to writeToFS() -> %s", f, p)
		}
	}
}
