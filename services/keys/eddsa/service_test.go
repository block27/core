package eddsa

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/test"

	"github.com/amanelis/bespin/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var Config config.Reader

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

	k1, err := NewEDDSA(c, "test-key-0")
	if err != nil {
		panic(err)
	}

	Key = k1.Struct()
	Config = c
}

func TestNewEDDSABlank(t *testing.T) {
	k, err := NewEDDSABlank(Config)
	if err != nil {
		t.Fail()
	}

	assertStructNilness(t, k)
}

func TestNewEDDSA(t *testing.T) {
	k, err := NewEDDSA(Config, "test-key-1")
	if err != nil {
		t.Fail()
	}

	assertStructCorrectness(t, k)
}

func TestGetECDSA(t *testing.T) {
	k, err := GetEDDSA(Config, Key.FilePointer())
	if err != nil {
		t.Fail()
	}

	assertStructCorrectness(t, k)
}

func TestListECDSA(t *testing.T) {
	keys, err := ListECDSA(Config)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) == 0 {
		t.Fatal("0 keys returned, should be < 1")
	}

	assertStructCorrectness(t, keys[0])
}

// TestVerifyReadability ...
// we should confirm that the keys saved with the gobencoder should be decoded
// and verified their identity/data pub/pri keys
func TestVerifyReadability(t *testing.T) {
	newKey, err := NewEDDSA(Config, "test-key-P")
	if err != nil {
		t.Fail()
	}

	assertStructCorrectness(t, newKey)

	getKey, e := GetEDDSA(Config, newKey.FilePointer())
	if e != nil {
		t.Fail()
	}

	assertStructCorrectness(t, getKey)

	path := fmt.Sprintf("%s/%s", Config.GetString("paths.keys"), getKey.FilePointer())
	t.Logf("Path reference: %s\n", path)

	priBytes, perr := helpers.ReadBinary(fmt.Sprintf("%s/private.key", path))
	if perr != nil {
		t.Fatal(perr)
	}

	pubBytes, perr := helpers.ReadBinary(fmt.Sprintf("%s/public.key", path))
	if perr != nil {
		t.Fatal(perr)
	}

	// Must first load the key found
	getKey.Struct().privateKey.FromBytes(priBytes)
	getKey.Struct().publicKey.FromBytes(pubBytes)

	pPubKey, pPubErr := getKey.Struct().getPublicKey()
	if pPubErr != nil {
		t.Fatal(pPubErr)
	}

	pPriKey, pPriErr := getKey.Struct().getPrivateKey()
	if pPriErr != nil {
		t.Fatal(pPriErr)
	}

	t.Logf("publicKey(get): %x\n", getKey.Struct().privateKey.pubKey.pubKey)
	t.Logf("publicKey(new): %x\n", *pPubKey)

	if !test.ByteEq(t, getKey.Struct().privateKey.pubKey.pubKey, *pPubKey) {
		t.Fatal("publicKeys do not match")
	}

	t.Logf("privateKeys(get): %x\n", getKey.Struct().privateKey.privKey)
	t.Logf("privateKeys(new): %x\n", *pPriKey)

	if !test.ByteEq(t, getKey.Struct().privateKey.privKey, *pPriKey) {
		t.Fatal("privateKeys do not match")
	}
}

func TestKeypair(t *testing.T) {
	assert := assert.New(t)

	var shortBuffer = []byte("Short Buffer")

	privKey, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeypair()")

	var privKey2 privateKey
	assert.Error(privKey2.FromBytes(shortBuffer), "PrivateKey.FromBytes(short)")

	err = privKey2.FromBytes(privKey.Bytes())
	assert.NoError(err, "PrivateKey.ToBytes()->FromBytes()")
	assert.Equal(privKey, &privKey2, "PrivateKey.ToBytes()->FromBytes()")

	privKey2.Reset()
	assert.True(utils.CtIsZero(privKey2.privKey), "PrivateKey.Reset()")

	var pubKey publicKey
	assert.Error(pubKey.FromBytes(shortBuffer), "PublicKey.FromBytes(short)")

	err = pubKey.FromBytes(privKey.PublicKey().Bytes())
	assert.NoError(err, "PrivateKey.PublicKey().Bytes->FromBytes()")
	assert.Equal(privKey.PublicKey(), &pubKey, "PrivateKey.PublicKey().Bytes->FromBytes()")

	pkArr := pubKey.ByteArray()
	assert.Equal(privKey.PublicKey().Bytes(), pkArr[:], "PrivateKey.PublicKey().Bytes()->pubKey.ByteArray()")
}

func TestEdDSAOps(t *testing.T) {
	assert := assert.New(t)

	privKey, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeypair()")
	pubKey := privKey.PublicKey()

	msg := []byte("The year was 2081, and everybody was finally equal.  They weren't only equal before God and the law.  They were equal every which way.  Nobody was smarter than anybody else.  Nobody was better looking than anybody else.  Nobody was stronger or quicker than anybody else.  All this equality was due to the 211th, 212th, and 213th Amendments to the Constitution, and to the unceasing vigilance of agents of the United States Handicapper General.")

	sig := privKey.Sign(msg)
	assert.Equal(SignatureSize, len(sig), "Sign() length")
	assert.True(pubKey.Verify(sig, msg), "Verify(sig, msg)")
	assert.False(pubKey.Verify(sig, msg[:16]), "Verify(sig, msg[:16])")

	dhPrivKey := privKey.ToECDH()
	dhPubKey := privKey.PublicKey().ToECDH()
	assert.True(dhPrivKey.PublicKey().Equal(dhPubKey), "ToECDH() basic sanity")
}

func assertStructCorrectness(t *testing.T, k KeyAPI) {
	t.Helper()

	assert.NotNil(t, k.Struct().GID)
	assert.NotNil(t, k.Struct().Name)
	assert.NotNil(t, k.Struct().Slug)
	assert.NotNil(t, k.Struct().FingerprintMD5)
	assert.NotNil(t, k.Struct().FingerprintSHA)

	assert.NotNil(t, k.Struct().PrivatePemPath)
	assert.NotNil(t, k.Struct().PrivateKeyB64)
	assert.NotNil(t, k.Struct().PublicKeyB64)
	assert.NotNil(t, k.Struct().PrivateKeyPath)
	assert.NotNil(t, k.Struct().PublicKeyPath)

	assert.Equal(t, k.Struct().Status, "active")
	assert.Equal(t, k.Struct().KeyType, "eddsa.PrivateKey <==> ed25519")
}

func assertStructNilness(t *testing.T, k KeyAPI) {
	assert.Equal(t, k.Struct().GID.String(), "00000000-0000-0000-0000-000000000000")
	assert.Equal(t, k.Struct().Name, "")
	assert.Equal(t, k.Struct().Slug, "")
	assert.Equal(t, k.Struct().Status, "")
	assert.Equal(t, k.Struct().KeyType, "")
	assert.Equal(t, k.Struct().FingerprintMD5, "")
	assert.Equal(t, k.Struct().FingerprintSHA, "")

	assert.Equal(t, k.Struct().PrivatePemPath, "")
	assert.Equal(t, k.Struct().PrivateKeyB64, "")
	assert.Equal(t, k.Struct().PublicKeyB64, "")
	assert.Equal(t, k.Struct().PrivateKeyPath, "")
	assert.Equal(t, k.Struct().PublicKeyPath, "")
}
