package ec

import (
	"fmt"
	"os"
	"reflect"
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

	spew.Dump(k1)

	Key = k1.Struct()
	Config = c
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

	AssertStructCorrectness(t, k, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k, "NewEC")
	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k.FilePointer()))
}

func TestGetEC(t *testing.T) {
	// Valid
	k, err := GetEC(Config, Key.FilePointer())
	if err != nil {
		t.Fatalf(err.Error())
	}

	if !reflect.DeepEqual(k.GetAttributes(), Key.GetAttributes()) {
		t.Fail()
	}

	if !reflect.DeepEqual(k, Key) {
		t.Fail()
	}

	gPk1, err := k.getPrivateKey()
	if err != nil {
		t.Fail()
	}

	gPk2, err := Key.getPrivateKey()
	if err != nil {
		t.Fail()
	}

	gPp1, err := k.getPublicKey()
	if err != nil {
		t.Fail()
	}

	gPp2, err := Key.getPublicKey()
	if err != nil {
		t.Fail()
	}

	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k, "NewEC")
}

func TestGetPrivateKey(t *testing.T) {
	// Test from New -------------------------------------------------------------
	k1, err := NewEC(Config, "test-key-1", "prime256v1")
	if err != nil {
		t.Fatalf(err.Error())
	}

	gPk1, err := k1.getPrivateKey()
	if err != nil {
		t.Fail()
	}

	gPp1, err := gPk1.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fail()
	}

	AssertStructCorrectness(t, k1, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k1, "NewEC")

	// Test from Get -------------------------------------------------------------
	k2, err := GetEC(Config, k1.FilePointer())
	if err != nil {
		t.Fatalf(err.Error())
	}

	gPk2, err := k2.getPrivateKey()
	if err != nil {
		t.Fail()
	}

	gPp2, err := gPk2.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fail()
	}

	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k2, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k2, "NewEC")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k1.FilePointer()))
}

func TestGetPublicKey(t *testing.T) {
	// Test from New -------------------------------------------------------------
	k1, err := NewEC(Config, "test-key-1", "prime256v1")
	if err != nil {
		t.Fatalf(err.Error())
	}

	gPk1, err := k1.getPublicKey()
	if err != nil {
		t.Fail()
	}

	gPp1, err := gPk1.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fail()
	}

	AssertStructCorrectness(t, k1, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k1, "NewEC")

	// Test from Get -------------------------------------------------------------
	k2, err := GetEC(Config, k1.FilePointer())
	if err != nil {
		t.Fatalf(err.Error())
	}

	gPk2, err := k2.getPublicKey()
	if err != nil {
		t.Fail()
	}

	gPp2, err := gPk2.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fail()
	}

	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k2, "privateKey", "prime256v1")
	CheckFullKeyFileObjects(t, Config, k2, "NewEC")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k1.FilePointer()))
}

func TestKeyID(t *testing.T) {
	if Key.FilePointer() != Key.KeyID().String() || Key.Attributes.GID != Key.KeyID() {
		t.Fail()
	}
}
