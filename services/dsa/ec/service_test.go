package ec

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/amanelis/core-zero/config"
	"github.com/amanelis/core-zero/helpers"
	"github.com/amanelis/core-zero/services/dsa"
	"github.com/davecgh/go-spew/spew"
)

var Config config.Reader
var Curves = []string{
	"prime256v1",
	// "secp224r1",
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

	AssertStructCorrectness(t, k, dsa.Private, "prime256v1")
	CheckFullKeyFileObjects(t, Config, k, "NewEC")
	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k.GetAttributes().FilePointer()))
}

func TestGetEC(t *testing.T) {
	// Valid
	k, err := GetEC(Config, Key.GetAttributes().FilePointer())
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

	// ---------------------------------------------------------------------------
	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k, dsa.Private, "prime256v1")
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

	AssertStructCorrectness(t, k1, dsa.Private, "prime256v1")
	CheckFullKeyFileObjects(t, Config, k1, "NewEC")

	// Test from Get -------------------------------------------------------------
	k2, err := GetEC(Config, k1.GetAttributes().FilePointer())
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

	// ---------------------------------------------------------------------------
	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k2, dsa.Private, "prime256v1")
	CheckFullKeyFileObjects(t, Config, k2, "NewEC")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k1.GetAttributes().FilePointer()))
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

	AssertStructCorrectness(t, k1, dsa.Private, "prime256v1")
	CheckFullKeyFileObjects(t, Config, k1, "NewEC")

	// Test from Get -------------------------------------------------------------
	k2, err := GetEC(Config, k1.GetAttributes().FilePointer())
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

	// ---------------------------------------------------------------------------
	if !reflect.DeepEqual(gPk1, gPk2) {
		t.Fail()
	}

	if !reflect.DeepEqual(gPp1, gPp2) {
		t.Fail()
	}

	AssertStructCorrectness(t, k2, dsa.Private, "prime256v1")
	CheckFullKeyFileObjects(t, Config, k2, "NewEC")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
		k1.GetAttributes().FilePointer()))
}

func BenchmarkSignP256(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewEC(Config, "bench-key-256", "prime256v1")
	if err != nil {
		b.Fail()
	}

	_, e := k.getPrivateKey()
	if e != nil {
		b.Fail()
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			k.Sign(hashed)
		}
	})
}

func BenchmarkSignSecp384r1(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewEC(Config, "bench-key-384", "secp384r1")
	if err != nil {
		b.Fail()
	}

	_, e := k.getPrivateKey()
	if e != nil {
		b.Fail()
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			k.Sign(hashed)
		}
	})
}

func BenchmarkSignSecp521r1(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewEC(Config, "bench-key-521", "secp521r1")
	if err != nil {
		b.Fail()
	}

	_, e := k.getPrivateKey()
	if e != nil {
		b.Fail()
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			k.Sign(hashed)
		}
	})
}

func TestSign(t *testing.T) {
	if _, err := Key.Sign([]byte("the quick brown fox jumps over the lazy dog")); err != nil {
		t.Fail()
	}
}

func TestSignEC(t *testing.T) {
	t.Parallel()

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sign/verify:prime256v1", func(t *testing.T) {
		t.Parallel()

		key, err := NewEC(Config, "sign/verify:test1", "prime256v1")
		if err != nil {
			t.Fail()
		}

		sig, err := key.Sign(data)
		if err != nil {
			t.Fail()
		}

		t.Logf("Signature (prime256v1): %s\n", spew.Sdump(sig))

		if !key.Verify(data, sig) {
			t.Fail()
		}

		AssertStructCorrectness(t, key, dsa.Private, "prime256v1")
		CheckFullKeyFileObjects(t, Config, key, "NewEC")

		ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
			key.GetAttributes().FilePointer()))
	})

	t.Run("sign/verify:secp384r1", func(t *testing.T) {
		t.Parallel()

		key, err := NewEC(Config, "sign/verify:test2", "secp384r1")
		if err != nil {
			t.Fail()
		}

		sig, err := key.Sign(data)
		if err != nil {
			t.Fail()
		}

		t.Logf("Signature (secp384r1): %s\n", spew.Sdump(sig))

		if !key.Verify(data, sig) {
			t.Fail()
		}

		AssertStructCorrectness(t, key, dsa.Private, "secp384r1")
		CheckFullKeyFileObjects(t, Config, key, "NewEC")

		ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
			key.GetAttributes().FilePointer()))
	})

	t.Run("sign/verify:secp521r1", func(t *testing.T) {
		t.Parallel()

		key, err := NewEC(Config, "sign/verify:test3", "secp521r1")
		if err != nil {
			t.Fail()
		}

		sig, err := key.Sign(data)
		if err != nil {
			t.Fail()
		}

		t.Logf("Signature (secp521r1): %s\n", spew.Sdump(sig))

		if !key.Verify(data, sig) {
			t.Fail()
		}

		AssertStructCorrectness(t, key, dsa.Private, "secp521r1")
		CheckFullKeyFileObjects(t, Config, key, "NewEC")

		ClearSingleTestKey(t, fmt.Sprintf("%s/ec/%s", Config.GetString("paths.keys"),
			key.GetAttributes().FilePointer()))
	})
}

func TestImportPublicEC(t *testing.T) {
	t.Parallel()

	t.Run("import:prime256v1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/prime256v1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		k, e := ImportPublicEC(Config, "prime256v1-name", "prime256v1", pub.GetBody())
		if e != nil {
			t.Fatal(e)
		}

		AssertStructCorrectness(t, k, dsa.Public, "prime256v1")
	})

	t.Run("import:secp384r1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp384r1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		k, e := ImportPublicEC(Config, "secp384r1-name", "secp384r1", pub.GetBody())
		if e != nil {
			t.Fatal(e)
		}

		AssertStructCorrectness(t, k, dsa.Public, "secp384r1")
	})

	t.Run("import:secp521r1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp521r1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		k, e := ImportPublicEC(Config, "secp521r1-name", "secp521r1", pub.GetBody())
		if e != nil {
			t.Fatal(e)
		}

		AssertStructCorrectness(t, k, dsa.Public, "secp521r1")
	})
}
