package ecdsa

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	"github.com/amanelis/core-zero/config"
	"github.com/amanelis/core-zero/helpers"
	"github.com/amanelis/core-zero/test"

	enc "github.com/amanelis/core-zero/services/dsa/ecdsa/encodings"
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

	k1, err := NewECDSA(c, "test-key-0", "prime256v1")
	if err != nil {
		panic(err)
	}

	spew.Dump(k1)

	Key = k1.Struct()
	Config = c
}

func TestNewECDSABlank(t *testing.T) {
	k, err := NewECDSABlank(Config)
	if err != nil {
		t.Fail()
	}

	AssertStructNilness(t, k)
}

func TestImportPublicECDSA(t *testing.T) {
	t.Parallel()

	t.Run("import:prime256v1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/prime256v1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		// Check validity / only should be done in 1 test case
		// -------------------------------------------------------------------------
		// Empty "name"
		_, e := ImportPublicECDSA(Config, "", "secp521r1", pub.GetBody())
		if e == nil {
			t.Fatal(e)
		}

		// Empty "curve"
		_, r := ImportPublicECDSA(Config, "some-name", "", pub.GetBody())
		if r == nil {
			t.Fatal(r)
		}

		// Invalid curve
		_, p := ImportPublicECDSA(Config, "some-name", "junk1024r1", pub.GetBody())
		if p == nil {
			t.Fatal(p)
		}

		// Invalid pub
		_, j := ImportPublicECDSA(Config, "some-name", "secp521r1", []byte("junk..."))
		if j == nil {
			t.Fatal(j)
		}

		k1, e := ImportPublicECDSA(Config, "prime256v1-name", "prime256v1", pub.GetBody())
		if e != nil {
			t.Fail()
		}

		AssertStructCorrectness(t, k1, "PublicKey", "prime256v1")

		if k1.Struct().Name != "prime256v1-name" {
			t.Fail()
		}

		if k1.Struct().KeyType != "ecdsa.PublicKey <==> prime256v1" {
			t.Fail()
		}

		t.Logf("successfully imported [prime256v1-pubkey] [%s]", k1.FilePointer())

		ClearSingleTestKey(t, fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"),
			k1.FilePointer()))
	})

	t.Run("import:secp384r1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp384r1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		k1, e := ImportPublicECDSA(Config, "secp384r1-name", "secp384r1", pub.GetBody())
		if e != nil {
			t.Fail()
		}

		AssertStructCorrectness(t, k1, "PublicKey", "secp384r1")

		if k1.Struct().Name != "secp384r1-name" {
			t.Fail()
		}

		if k1.Struct().KeyType != "ecdsa.PublicKey <==> secp384r1" {
			t.Fail()
		}

		t.Logf("successfully imported [secp384r1-pubkey] [%s]", k1.FilePointer())

		ClearSingleTestKey(t, fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"),
			k1.FilePointer()))
	})

	t.Run("import:secp521r1", func(t *testing.T) {
		t.Parallel()

		pub, err := helpers.NewFile("../../../data/keys/ecdsa/secp521r1-pubkey.pem")
		if err != nil {
			t.Fail()
		}

		k1, e := ImportPublicECDSA(Config, "secp521r1-name", "secp521r1", pub.GetBody())
		if e != nil {
			t.Fatal(e)
		}

		AssertStructCorrectness(t, k1, "PublicKey", "secp521r1")

		if k1.Struct().Name != "secp521r1-name" {
			t.Fatalf("k1.Struct().Name did not equal expected valud: %s", k1.Struct().Name)
		}

		if k1.Struct().KeyType != "ecdsa.PublicKey <==> secp521r1" {
			t.Fatal("invalid key type")
		}

		t.Logf("successfully imported [secp521r1-pubkey] [%s]", k1.FilePointer())

		ClearSingleTestKey(t, fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"),
			k1.FilePointer()))
	})
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

	AssertStructCorrectness(t, k, "PrivateKey", "prime256v1")

	c := elliptic.P256()
	p, e := k.getPrivateKey()
	if e != nil {
		t.Fail()
	}

	if !c.IsOnCurve(p.PublicKey.X, p.PublicKey.Y) {
		t.Fail()
	}

	// Check for filesystem keys are present
	CheckFullKeyFileObjects(t, Config, k, "NewECDSA")

	ClearSingleTestKey(t, fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"),
		k.FilePointer()))
}

// TestVerifyReadability ...
// we should confirm that the keys saved with the gobencoder should be decoded
// and verified their identity/data pub/pri keys
func TestVerifyReadability(t *testing.T) {
	getKey, e := GetECDSA(Config, Key.FilePointer())
	if e != nil {
		t.Fail()
	}

	AssertStructCorrectness(t, getKey, "PrivateKey", "prime256v1")

	path := fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"), getKey.FilePointer())
	t.Logf("Path reference: %s\n", path)

	priBytes, _ := helpers.ReadBinary(fmt.Sprintf("%s/private.key", path))
	datPri, datErr := x509.ParseECPrivateKey(priBytes)
	if datErr != nil {
		t.Fatal(datErr)
	}

	getPri, getErr := getKey.getPrivateKey()
	if getErr != nil || getPri == nil {
		t.Fatal(getErr)
	}

	// Test PrivateKey
	t.Logf("getPri(D): %x\n", getPri.D.Bytes())
	t.Logf("datPri(D): %x\n", datPri.D.Bytes())
	if !test.ByteEq(t, getPri.D.Bytes(), datPri.D.Bytes()) {
		t.Fatal("getPri(D).Bytes: did not match datPri")
	}

	t.Logf("getPri(X): %x\n", getPri.X.Bytes())
	t.Logf("datPri(X): %x\n", datPri.X.Bytes())
	if !test.ByteEq(t, getPri.X.Bytes(), datPri.X.Bytes()) {
		t.Fatal("getPri(X).Bytes: did not match datPri")
	}

	t.Logf("getPri(Y): %x\n", getPri.Y.Bytes())
	t.Logf("datPri(Y): %x\n", datPri.Y.Bytes())
	if !test.ByteEq(t, getPri.Y.Bytes(), datPri.Y.Bytes()) {
		t.Fatal("getPri(Y).Bytes: did not match datPri")
	}

	// Test PublicKey
	if !test.ByteEq(t, getPri.PublicKey.X.Bytes(), datPri.PublicKey.X.Bytes()) {
		t.Fatal("getPri.pub(X).Bytes: did not match datPri.PublicKey")
	}

	if !test.ByteEq(t, getPri.PublicKey.Y.Bytes(), datPri.PublicKey.Y.Bytes()) {
		t.Fatal("getPri.pub(Y).Bytes: did not match datPri.PublicKey")
	}

	if getPri.Params().BitSize != 256 {
		t.Fatal("getPri: bitsize did not match")
	}

	if datPri.Params().BitSize != 256 {
		t.Fatal("datPri: bitsize did not match")
	}

	pemKey1, pemPub1, pemErr1 := enc.Encode(getPri, &getPri.PublicKey)
	if pemErr1 != nil {
		t.Fatal("Failed: enc.Encode(1)")
	}

	pemKey2, pemPub2, pemErr2 := enc.Encode(datPri, &datPri.PublicKey)
	if pemErr2 != nil {
		t.Fatal("Failed: enc.Encode(2)")
	}

	if pemKey1 != pemKey2 {
		t.Fatal("pemKey1 != pemKey2")
	}

	if pemPub1 != pemPub2 {
		t.Fatal("pemPub1 != pemPub2")
	}
}

func BenchmarkSignP224(b *testing.B) {
	b.ResetTimer()
	hashed := []byte("testing")

	k, err := NewECDSA(Config, "bench-key-224", "secp224r1")
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

	k, err := NewECDSA(Config, "bench-key-256", "prime256v1")
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

	k, err := NewECDSA(Config, "bench-key-384", "secp384r1")
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

	k, err := NewECDSA(Config, "bench-key-521", "secp521r1")
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

	k, err := NewECDSA(Config, "bench-key-224", "secp224r1")
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

	k, err := NewECDSA(Config, "bench-key-256", "prime256v1")
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

	k, err := NewECDSA(Config, "bench-key-384", "secp384r1")
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

	k, err := NewECDSA(Config, "bench-key-521", "secp521r1")
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
	k, err := GetECDSA(Config, Key.FilePointer())
	if err != nil {
		t.Fail()
	}

	AssertStructCorrectness(t, k, "PrivateKey", "prime256v1")
}

func TestListECDSA(t *testing.T) {
	keys, err := ListECDSA(Config)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) == 0 {
		t.Fatal("0 keys returned, should be < 1")
	}

	for _, k := range keys {
		if k.FilePointer() == Key.FilePointer() {
			AssertStructCorrectness(t, k, "PrivateKey", "prime256v1")
			break
		}
	}
}

func TestGetCurve(t *testing.T) {
	for _, curve := range Curves {
		if _, c, e := getCurve(curve); e != nil || c != curve {
			t.Fatalf("failed to getCurve on %s", curve)
		}
	}

	// invalid
	if _, _, e := getCurve("junk"); e == nil {
		t.Fail()
	}
}

func TestFilePointer(t *testing.T) {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if !r.MatchString(Key.FilePointer()) {
		t.Fail()
	}
}

func TestKeyID(t *testing.T) {
	if Key.FilePointer() != Key.KeyID().String() || Key.GID != Key.KeyID() {
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

	t.Logf("signature: (r=0x%x, s=0x%x)\n", sig.R, sig.S)

	valid := Key.Verify(hash[:], sig)
	t.Log("verified: ", valid)
}

func TestSignAndVerify(t *testing.T) {
	hashed := []byte("testing")

	sig, err := Key.Sign(hashed)
	if err != nil {
		t.Fail()
	}

	t.Logf("signature: (r=0x%x, s=0x%x)\n", sig.R, sig.S)

	valid := Key.Verify(hashed[:], sig)
	t.Log("verified: ", valid)

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
	// Invalid
	_, err := Key.Unmarshall("BNT+QMkvQZwszvyXMyk#WH6rj46AMEWRreKDK7W4p5yM2kxvN")
	if err == nil {
		t.Fatal("unmarshall with invalid data did not fail")
	}

	k, e := GetECDSA(Config, Key.FilePointer())
	if e != nil {
		t.Fail()
	}

	path := fmt.Sprintf("%s/ecdsa/%s", Config.GetString("paths.keys"), k.FilePointer())
	obPa := fmt.Sprintf("%s/obj.bin", path)

	objBytes, objErr := helpers.ReadBinary(obPa)
	if objErr != nil {
		t.Fatal(objErr)
	}

	unmarshalled, err := k.Unmarshall(string(objBytes))
	if err != nil {
		t.Fatal(err)
	}

	keyPri, keyErr := k.getPrivateKey()
	if keyErr != nil {
		t.Fatal(keyErr)
	}

	unmPri, unmErr := unmarshalled.getPrivateKey()
	if unmErr != nil {
		t.Fatal(unmErr)
	}

	if keyPri.D.BitLen() != unmPri.D.BitLen() {
		t.Fatal("keyPri.D.BitLen() != unmPri.D.BitLen()")
	}
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
	file := fmt.Sprintf("%s/ecdsa/%s/obj.bin", Config.GetString("paths.keys"), Key.FilePointer())
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
