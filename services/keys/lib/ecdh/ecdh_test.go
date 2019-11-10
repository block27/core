package ecdh

import (
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/amanelis/bespin/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func TestPrivateKey(t *testing.T) {
	assert := assert.New(t)

	var shortBuffer = []byte("Short Buffer")

	privKey, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeypair failed")

	var privKey2 PrivateKey
	assert.Error(privKey2.FromBytes(shortBuffer), "PrivateKey.FromBytes(short)")

	err = privKey2.FromBytes(privKey.Bytes())
	assert.NoError(err, "PrivateKey.ToBytes()->FromBytes()")
	assert.Equal(privKey, &privKey2, "PrivateKey.ToBytes()->FromBytes()")

	privKey2.Reset()
	assert.True(utils.CtIsZero(privKey2.Bytes()), "PrivateKey.Reset()")

	var pubKey PublicKey
	assert.Error(pubKey.FromBytes(shortBuffer), "PublicKey.FromBytes(short)")

	err = pubKey.FromBytes(privKey.PublicKey().Bytes())
	assert.NoError(err, "PrivateKey.PublicKey().Bytes->FromBytes()")
	assert.Equal(privKey.PublicKey(), &pubKey, "PrivateKey.PublicKey().Bytes->FromBytes()")
}

func TestECDHOps(t *testing.T) {
	assert := assert.New(t)

	aliceKeypair, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeygen() Alice failed")

	var bobSk, bobPk, aliceS, bobS, tmp [GroupElementLength]byte
	_, err = rand.Read(bobSk[:])
	require.NoError(t, err, "failed to generate bobSk")
	curve25519.ScalarBaseMult(&bobPk, &bobSk)

	curve25519.ScalarBaseMult(&tmp, &aliceKeypair.privBytes)
	assert.Equal(aliceKeypair.PublicKey().Bytes(), tmp[:], "ExpG() mismatch against X25519 scalar base mult")

	Exp(&aliceS, &bobPk, &aliceKeypair.privBytes)
	copy(tmp[:], aliceKeypair.PublicKey().Bytes())
	curve25519.ScalarMult(&bobS, &bobSk, &tmp)
	assert.Equal(bobS, aliceS, "Exp() mismatch against X25519 scalar mult")
}

func TestPublicKeyToFromPEMFile(t *testing.T) {
	assert := assert.New(t)
	aliceKeypair, err := NewKeypair(rand.Reader)
	assert.NoError(err)
	f, err := ioutil.TempFile("", "alice.pem")
	assert.NoError(err)
	err = aliceKeypair.PublicKey().ToPEMFile(f.Name())
	assert.NoError(err)
	pubKey := new(PublicKey)
	err = pubKey.FromPEMFile(f.Name())
	assert.NoError(err)
	assert.Equal(pubKey.Bytes(), aliceKeypair.PublicKey().Bytes())
}
