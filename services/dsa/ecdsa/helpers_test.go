package ecdsa

import (
	"fmt"
	"os"
	"testing"

	"github.com/amanelis/bespin/config"
	h "github.com/amanelis/bespin/helpers"
)

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
		if !h.FileExists(p) {
			t.Fatalf("%s failed to writeToFS() -> %s", f, p)
		}
	}
}
