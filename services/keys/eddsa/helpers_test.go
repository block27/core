package eddsa

import (
	"fmt"
	"testing"

	"github.com/amanelis/bespin/config"
	h "github.com/amanelis/bespin/helpers"
)

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
