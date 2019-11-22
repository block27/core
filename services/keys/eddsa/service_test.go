package eddsa

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/amanelis/bespin/config"

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

func TestNewED25519Blank(t *testing.T) {
	result, err := NewED25519Blank(Config)
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

	assert.Equal(t, result.Struct().PrivatePemPath, "")
	assert.Equal(t, result.Struct().PrivateKeyB64, "")
	assert.Equal(t, result.Struct().PublicKeyB64, "")
	assert.Equal(t, result.Struct().PrivateKeyPath, "")
	assert.Equal(t, result.Struct().PublicKeyPath, "")
}

func TestNewEDDSA(t *testing.T) {
	// Valid
	k, err := NewEDDSA(Config, "test-key-1")
	if err != nil {
		t.Fail()
	}

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

func TestKeypair(t *testing.T) {
	assert := assert.New(t)

	var shortBuffer = []byte("Short Buffer")

	privKey, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeypair()")

	var privKey2 PrivateKey
	assert.Error(privKey2.FromBytes(shortBuffer), "PrivateKey.FromBytes(short)")

	err = privKey2.FromBytes(privKey.Bytes())
	assert.NoError(err, "PrivateKey.ToBytes()->FromBytes()")
	assert.Equal(privKey, &privKey2, "PrivateKey.ToBytes()->FromBytes()")

	privKey2.Reset()
	assert.True(utils.CtIsZero(privKey2.privKey), "PrivateKey.Reset()")

	var pubKey PublicKey
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
