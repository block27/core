package ec

import (
	"fmt"
	"os"
	// "reflect"
	"testing"

	"github.com/amanelis/core-zero/config"
	"github.com/davecgh/go-spew/spew"
)

var Config config.Reader
var Curves = []string{
	"secp224r1",
	"prime256v1",
	"secp384r1",
	"secp521r1",
}

var Key *key

func init() {
	os.Setenv("ENVIRONMENT", "test")

	c, err := config.LoadConfig(config.Defaults)
	if err != nil {
		panic(err)
	}

	if c.GetString("environment") != "test" {
		panic(fmt.Errorf("test [environment] is not in [test] mode"))
	}

	k1, err := NewEC(c, "test-key-0", "prime256v1")
	if err != nil {
		panic(err)
	}

	Key = k1.Struct()
	Config = c
}

func TestKeyID(t *testing.T) {
	if Key.FilePointer() != Key.KeyID().String() || Key.Attributes.GID != Key.KeyID() {
		t.Fail()
	}
}

func TestNewEC(t *testing.T) {
	// Invalid curve
	_, q := NewEC(Config, "test-key-1", "prim56v1")
	if q == nil {
		t.Fatal("invalid curve")
	}

	// Valid
	k, err := NewEC(Config, "test-key-1", "prime256v1")
	if err != nil {
		t.Fatalf(err.Error())
	}

	if k.GetAttributes().KeyType != "ec.privateKey <==> prime256v1" {
		t.Fatalf(k.GetAttributes().KeyType)
	}

	if k == nil {
		t.Fail()
	}
}

func TestNewECDSA(t *testing.T) {
	// Invalid curve
	_, q := NewEC(Config, "test-key-1", "prim56v1")
	if q == nil {
		t.Fatal("invalid curve")
	}

	// Valid
	k, err := NewEC(Config, "test-key-1", "prime256v1")
	if err != nil {
		t.Fail()
	}

	AssertStructCorrectness(t, k, "privateKey", "prime256v1")

	// Check for filesystem keys are present
	CheckFullKeyFileObjects(t, Config, k, "NewECDSA")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"),
		k.FilePointer()))
}



func TestGetEC(t *testing.T) {
	// Valid
	k, err := GetEC(Config, Key.FilePointer())
	if err != nil {
		t.Fatalf(err.Error())
	}

	spew.Dump(k)

	if k == nil {
		t.Fail()
	}
}
