package keys

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/helpers"
)

var Config config.ConfigReader

var PrivateKey *ecdsa.PrivateKey
var PublicKey *ecdsa.PublicKey

var Key *key

func init() {
	os.Setenv("ENVIRONMENT", "test")

	c, err := config.LoadConfig(config.ConfigDefaults)
	if err != nil {
		panic(err)
	}

	if c.GetString("environment") != "test" {
		panic(fmt.Errorf("test [environment] is not in [test] mode"))
	}

	k1, err := NewECDSA(c, "test-key")
	if err != nil {
		panic(err)
	}

	Key = k1.Struct()
	Config = c
}

func TestStruct(t *testing.T) {
	assert.NotNil(t, Key.Struct().GID)
	assert.NotNil(t, Key.Struct().Fingerprint)
}

func TestGenerateUUID(t *testing.T) {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if !r.MatchString(generateUUID().String()) {
		t.Fail()
	}
}

func TestFilePointer(t *testing.T) {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if !r.MatchString(Key.FilePointer()) {
		t.Fail()
	}
}

func TestKeyToGOB64(t *testing.T) {
	gob64, err := keyToGOB64(Key)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}

	key64, err := keyFromGOB64(gob64)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}

	if err := checkFields(Key, key64); err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
}

func TestKeyFromGOB64(t *testing.T) {
	file := fmt.Sprintf("%s/%s/obj.bin", Config.GetString("paths.keys"), Key.FilePointer())
	data, err := helpers.ReadFile(file)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}

	key64, err := keyFromGOB64(data)
	if err != nil {
		t.Logf(err.Error())
		t.Fail()
	}

	if err := checkFields(Key, key64); err != nil {
		t.Logf(err.Error())
		t.Fail()
	}
}

func checkFields(original *key, copied *key) error {
	if original.GID != copied.Struct().GID {
		return fmt.Errorf("failed[GID]")
	}

	if original.Fingerprint != copied.Fingerprint {
		return fmt.Errorf("failed[Fingerprint]")
	}

	if original.PrivateKeyB64 != copied.PrivateKeyB64 {
		return fmt.Errorf("failed[PrivateKeyB64]")
	}

	if original.PublicKeyB64 != copied.PublicKeyB64 {
		return fmt.Errorf("failed[PublicKeyB64]")
	}

	if original.PrivateKeyPath != copied.PrivateKeyPath {
		return fmt.Errorf("failed[PrivateKeyPath]")
	}

	if original.PrivatePemPath != copied.PrivatePemPath {
		return fmt.Errorf("failed[PrivatePemPath]")
	}

	return nil
}
