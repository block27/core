package ec

import (
	"fmt"
	"os"

	// "reflect"
	"testing"

	"github.com/block27/core/config"
	// "github.com/block27/core/helpers"
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

	if k == nil {
		t.Fail()
	}

	fmt.Println(k)

	// if !reflect.DeepEqual(k, obj) {
	// 	t.Fatalf("structs don't equal?")
	// }

}
