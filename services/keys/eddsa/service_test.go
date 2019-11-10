package eddsa

import (
	"crypto/rand"
	"testing"

	"github.com/amanelis/bespin/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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