package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
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

	k1, err := NewECDSA(c, "test-key-0", "prime256v1")
	if err != nil {
		panic(err)
	}

	Key = k1.Struct()
	Config = c
}

func TestNewECDSABlank(t *testing.T) {
	result, err := NewECDSABlank(Config)
	if err != nil {
		t.Fail()
	}

	assert.Equal(t, result.Struct().GID.String(), "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, result.Struct().Name, "")
	assert.Equal(t, result.Struct().Slug, "")
	assert.Equal(t, result.Struct().Status, "")
	assert.Equal(t, result.Struct().KeyType, "")
	assert.Equal(t, result.Struct().FingerprintMD5, "")
	assert.Equal(t, result.Struct().FingerprintSHA, "")
}

func TestImportPublicECDSA256v1(t *testing.T) {
	pub, err := helpers.NewFile("../../../data/keys/ecdsa/prime256v1-pubkey.pem")
	if err != nil {
		t.Fail()
	}

	k1, e := ImportPublicECDSA("some-name", "prime256v1", pub.GetBody())
	if e != nil {
		t.Fail()
	}

	if k1.Struct().Name != "some-name" {
		t.Fail()
	}

	if k1.Struct().KeyType != "ecdsa.PublicKey <==> prime256v1" {
		t.Fail()
	}

	t.Log("successfully imported [prime256v1-pubkey]")
}

func TestImportPublicECDSA384r1(t *testing.T) {
	pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp384r1-pubkey.pem")
	if err != nil {
		t.Fail()
	}

	k1, e := ImportPublicECDSA("some-name", "secp384r1", pub.GetBody())
	if e != nil {
		t.Fail()
	}

	if k1.Struct().Name != "some-name" {
		t.Fail()
	}

	if k1.Struct().KeyType != "ecdsa.PublicKey <==> secp384r1" {
		t.Fail()
	}

	t.Log("successfully imported [secp384r1-pubkey]")
}

func TestImportPublicECDSA512r1(t *testing.T) {
	pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp521r1-pubkey.pem")
	if err != nil {
		t.Fail()
	}

	// Empty "name"
	_, e := ImportPublicECDSA("", "secp521r1", pub.GetBody())
	if e == nil {
		t.Fatal(e)
	}

	// Empty "curve"
	_, r := ImportPublicECDSA("some-name", "", pub.GetBody())
	if r == nil {
		t.Fatal(r)
	}

	// Invalid curve
	_, p := ImportPublicECDSA("some-name", "junk1024r1", pub.GetBody())
	if p == nil {
		t.Fatal(p)
	}

	// Invalid pub
	_, j := ImportPublicECDSA("some-name", "secp521r1", []byte("junk..."))
	if j == nil {
		t.Fatal(j)
	}

	// Valid key
	k1, e := ImportPublicECDSA("some-name", "secp521r1", pub.GetBody())
	if e != nil {
		t.Fatal(e)
	}

	if k1.Struct().Name != "some-name" {
		t.Fatalf("k1.Struct().Name did not equal expected valud: %s", k1.Struct().Name)
	}

	if k1.Struct().KeyType != "ecdsa.PublicKey <==> secp521r1" {
		t.Fatal("invalid key type")
	}

	t.Log("successfully imported [secp521r1-pubkey]")
}

func TestNewECDSA(t *testing.T) {
	// Invalid curve
	_, q := NewECDSA(Config, "test-key-1", "prim56v1")
	if q == nil {
		t.Fatal("invalid curve")
	}

	// Valid
	k, err := NewECDSA(Config, "test-key-1", "prime256v1")
	if err != nil {
		t.Fail()
	}

	c := elliptic.P256()
	p, e := k.getPrivateKey()
	if e != nil {
		t.Fail()
	}

	if !c.IsOnCurve(p.PublicKey.X, p.PublicKey.Y) {
		t.Fail()
	}
}

func BenchmarkSignP224(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-224", "secp224r1")
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

func BenchmarkSignP256(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-256", "prime256v1")
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

func BenchmarkSignP384(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-384", "secp384r1")
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

func BenchmarkSignP521(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-521", "secp521r1")
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

func BenchmarkVerifyP224(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-224", "secp224r1")
	if err != nil {
		b.Fail()
	}

	sig, _ := k.Sign(hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !k.Verify(hashed, sig) {
				b.Fail()
			}
		}
	})
}

func BenchmarkVerifyP256(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-256", "prime256v1")
	if err != nil {
		b.Fail()
	}

	sig, _ := k.Sign(hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !k.Verify(hashed, sig) {
				b.Fail()
			}
		}
	})
}

func BenchmarkVerifyP384(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-384", "secp384r1")
	if err != nil {
		b.Fail()
	}

	sig, _ := k.Sign(hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !k.Verify(hashed, sig) {
				b.Fail()
			}
		}
	})
}

func BenchmarkVerifyP521(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "test-key-521", "secp521r1")
	if err != nil {
		b.Fail()
	}

	sig, _ := k.Sign(hashed)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !k.Verify(hashed, sig) {
				b.Fail()
			}
		}
	})
}

func TestGetECDSA(t *testing.T) {
	result, err := GetECDSA(Config, Key.FilePointer())
	if err != nil {
		t.Fail()
	}

	assert.NotNil(t, result.Struct().GID)
	assert.NotNil(t, result.Struct().FingerprintMD5)
	assert.NotNil(t, result.Struct().FingerprintSHA)
}

func TestListECDSA(t *testing.T) {
	_, err := NewECDSA(Config, "context-key", "prime256v1")
	if err != nil {
		t.Fail()
	}

	result, err := ListECDSA(Config)
	if err != nil {
		t.Fail()
	}

	if len(result) == 0 {
		t.Fail()
	}
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

func TestSignandVerifyHuman(t *testing.T) {
	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	sig, err := Key.Sign(hash[:])
	if err != nil {
		t.Fail()
	}

	fmt.Printf("signature: (r=0x%x, s=0x%x)\n", sig.R, sig.S)

	valid := Key.Verify(hash[:], sig)
	fmt.Println("verified:", valid)
}

func TestSignAndVerify(t *testing.T) {
	hashed := []byte("testing")

	sig, err := Key.Sign(hashed)
	if err != nil {
		t.Fail()
	}

	fmt.Printf("signature: (r=0x%x, s=0x%x)\n", sig.R, sig.S)

	valid := Key.Verify(hashed[:], sig)
	fmt.Println("verified:", valid)

	if !valid {
		t.Fail()
	}
}

func TestPrintKey(t *testing.T) {
	t.Skip()
}

func TestMarshall(t *testing.T) {
	t.Skip()
}

func TestUnmarshall(t *testing.T) {
	t.Skip()
}

func TestGetPrivateKey(t *testing.T) {
	pKey, err := Key.getPrivateKey()
	if err != nil {
		t.Fail()
	}

	if pKey == nil {
		t.Fail()
	}
}

func TestGetPublicKey(t *testing.T) {
	pKey, err := Key.getPublicKey()
	if err != nil {
		t.Fail()
	}

	if pKey == nil {
		t.Fail()
	}
}

func TestStruct(t *testing.T) {
	assert.NotNil(t, Key.Struct().GID)
	assert.NotNil(t, Key.Struct().FingerprintMD5)
	assert.NotNil(t, Key.Struct().FingerprintSHA)
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
	if !reflect.DeepEqual(original.GID, copied.Struct().GID) {
		return fmt.Errorf("failed[GID]")
	}

	if !reflect.DeepEqual(original.Name, copied.Name) {
		return fmt.Errorf("failed[Name]")
	}

	if !reflect.DeepEqual(original.Slug, copied.Slug) {
		return fmt.Errorf("failed[Slug]")
	}

	if !reflect.DeepEqual(original.Status, copied.Status) {
		return fmt.Errorf("failed[Status]")
	}

	// if !reflect.DeepEqual(original.KeySize, copied.KeySize) {
	// 	return fmt.Errorf("failed[KeySize]")
	// }

	if !reflect.DeepEqual(original.FingerprintSHA, copied.FingerprintSHA) {
		return fmt.Errorf("failed[FingerprintSHA]")
	}

	if !reflect.DeepEqual(original.FingerprintMD5, copied.FingerprintMD5) {
		return fmt.Errorf("failed[FingerprintMD5]")
	}

	if !reflect.DeepEqual(original.PrivateKeyB64, copied.PrivateKeyB64) {
		return fmt.Errorf("failed[PrivateKeyB64]")
	}

	if !reflect.DeepEqual(original.PublicKeyB64, copied.PublicKeyB64) {
		return fmt.Errorf("failed[PublicKeyB64]")
	}

	if !reflect.DeepEqual(original.PublicKeyPath, copied.PublicKeyPath) {
		return fmt.Errorf("failed[PublicKeyPath]")
	}

	if !reflect.DeepEqual(original.PrivateKeyPath, copied.PrivateKeyPath) {
		return fmt.Errorf("failed[PrivateKeyPath]")
	}

	if !reflect.DeepEqual(original.PrivatePemPath, copied.PrivatePemPath) {
		return fmt.Errorf("failed[PrivatePemPath]")
	}

	return nil
}
