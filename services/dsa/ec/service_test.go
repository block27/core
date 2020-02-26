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

func init() {
	os.Setenv("ENVIRONMENT", "test")

	c, err := config.LoadConfig(config.Defaults)
	if err != nil {
		panic(err)
	}

	if c.GetString("environment") != "test" {
		panic(fmt.Errorf("test [environment] is not in [test] mode"))
	}

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
		t.Fail()
	}

	// p1Key, _ := k.getPrivateKey()
	// p2Key, _ := p1Key.MarshalPKCS1PrivateKeyPEM()
	// fmt.Println(string(p2Key))
	//
	// p1Pub, _ := k.getPublicKey()
	// p2Pub, _ := p1Pub.MarshalPKIXPublicKeyPEM()
	// fmt.Println(string(p2Pub))

	if k == nil {
		t.Fail()
	}

	spew.Dump(k)


	// if !reflect.DeepEqual(k, obj) {
	// 	t.Fatalf("structs don't equal?")
	// }


}
