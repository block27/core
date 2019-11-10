package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
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

	k1, err := NewECDSA(c, "test-key-0", 256)
	if err != nil {
		panic(err)
	}

	Key = k1.Struct()
	Config = c
}

func TestNewECDSA(t *testing.T) {
	k, err := NewECDSA(Config, "test-key-1", 256)
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

	k, err := NewECDSA(Config, "test-key-224", 224)
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

	k, err := NewECDSA(Config, "test-key-256", 256)
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

	k, err := NewECDSA(Config, "test-key-384", 384)
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

	k, err := NewECDSA(Config, "test-key-521", 521)
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

	k, err := NewECDSA(Config, "test-key-224", 224)
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

	k, err := NewECDSA(Config, "test-key-256", 256)
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

	k, err := NewECDSA(Config, "test-key-384", 384)
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

	k, err := NewECDSA(Config, "test-key-521", 521)
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

func TestNewECDSABlank(t *testing.T) {
	result, err := NewECDSABlank(Config)
	if err != nil {
		t.Fail()
	}

	assert.Equal(t, result.Struct().GID.String(), "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, result.Struct().Name, "")
	assert.Equal(t, result.Struct().Slug, "")
	assert.Equal(t, result.Struct().Status, "")
	assert.Equal(t, result.Struct().KeySize, 0)
	assert.Equal(t, result.Struct().FingerprintMD5, "")
	assert.Equal(t, result.Struct().FingerprintSHA, "")
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
	_, err := NewECDSA(Config, "context-key", 256)
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
	fmt.Println("signature verified:", valid)
}

func TestSignAndVerify(t *testing.T) {
	hashed := []byte("testing")

	sig, err := Key.Sign(hashed)
	if err != nil {
		t.Fail()
	}

	fmt.Printf("signature: (r=0x%x, s=0x%x)\n", sig.R, sig.S)

	valid := Key.Verify(hashed[:], sig)
	fmt.Println("signature verified:", valid)

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
	if original.GID != copied.Struct().GID {
		return fmt.Errorf("failed[GID]")
	}

	if original.Name != copied.Name {
		return fmt.Errorf("failed[Name]")
	}

	if original.Slug != copied.Slug {
		return fmt.Errorf("failed[Slug]")
	}

	if original.Status != copied.Status {
		return fmt.Errorf("failed[Status]")
	}

	if original.KeySize != copied.KeySize {
		return fmt.Errorf("failed[KeySize]")
	}

	if original.FingerprintSHA != copied.FingerprintSHA {
		return fmt.Errorf("failed[FingerprintSHA]")
	}

	if original.FingerprintMD5 != copied.FingerprintMD5 {
		return fmt.Errorf("failed[FingerprintMD5]")
	}

	if original.PrivateKeyB64 != copied.PrivateKeyB64 {
		return fmt.Errorf("failed[PrivateKeyB64]")
	}

	if original.PublicKeyB64 != copied.PublicKeyB64 {
		return fmt.Errorf("failed[PublicKeyB64]")
	}

	if original.PublicKeyPath != copied.PublicKeyPath {
		return fmt.Errorf("failed[PublicKeyPath]")
	}

	if original.PrivateKeyPath != copied.PrivateKeyPath {
		return fmt.Errorf("failed[PrivateKeyPath]")
	}

	if original.PrivatePemPath != copied.PrivatePemPath {
		return fmt.Errorf("failed[PrivatePemPath]")
	}

	return nil
}
