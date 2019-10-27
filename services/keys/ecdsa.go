package keys

import (
	// "bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"sync"
	// "crypto/sha1"
	"crypto/rand"
	"crypto/x509"
	// "encoding/binary"
	"encoding/base64"
	"encoding/pem"
	"os"

	guuid "github.com/google/uuid"
)

type KeyAPI interface {
	Struct() *key
}

// key - struct, main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage.
type key struct {
	sink sync.Mutex // mutex to allow clean concurrent access
	GID  guuid.UUID // guuid for crypto identification

	PublicKeyPath  string
	PrivateKeyPath string

	PublicKeyB64  string
	PrivateKeyB64 string
}

// func FindKey(c config.ConfigReader, ndx string) (key, error) {
// 	var k key
//
// 	r := c.GetStringMap(fmt.Sprintf("keys.%s", ndx))
// 	mapstructure.Decode(r, &k)
//
// 	return k, nil
// }
//
// func SaveKey(c config.ConfigReader, ndx string, val key) {
// 	c.SetDefault(fmt.Sprintf("keys.%s", ndx), val.Struct())
// 	c.WriteConfig()
// }

func NewKey() (KeyAPI, error) {
	key := &key{
		GID: generateUUID(),
	}

	// Create the curve
	c := elliptic.P256()

	sec, _ := ecdsa.GenerateKey(c, rand.Reader)
	pub := &sec.PublicKey

	// PEM #1
	pKey, pPub := encode(sec, pub)

	key.PublicKeyB64 = base64.StdEncoding.EncodeToString([]byte(pPub))
	key.PrivateKeyB64 = base64.StdEncoding.EncodeToString([]byte(pKey))

	// PEM #2
	// prpem := exportPrivateKeytoPEM(sec)
	// fmt.Printf("prpem: \n%s\n", prpem)
	//
	// pupem := exportPublicKeytoPEM(pub)
	// fmt.Printf("pupem: \n%s\n", pupem)

	return key, nil
}

func (k *key) Struct() *key {
	return k
}

func generateUUID() guuid.UUID {
	return guuid.New()
}

func importPublicKeyfromPEM(pempub []byte) *ecdsa.PublicKey {
	block, _ := pem.Decode(pempub)
	//log.Print(block)
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//log.Print(pubInterface)
	pub := pubInterface.(*ecdsa.PublicKey)
	//log.Print(pub)
	return pub
}

// export public key to pem format
func exportPublicKeytoPEM(pub *ecdsa.PublicKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(pub)
	c := pem.Block{
		Type:    "EC PUBLIC KEY",
		Headers: nil,
		Bytes:   b,
	}
	d := pem.EncodeToMemory(&c)
	//log.Print(string(d))

	return d
}

// import private key from pem format
func importPrivateKeyfromPEM(pemsec []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(pemsec)
	//log.Print(block)
	sec, _ := x509.ParseECPrivateKey(block.Bytes)
	//log.Print(sec)
	return sec
}

// export private key to pem format
func exportPrivateKeytoPEM(sec *ecdsa.PrivateKey) []byte {
	l, _ := x509.MarshalECPrivateKey(sec)
	m := pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   l,
	}
	n := pem.EncodeToMemory(&m)

	keypem, _ := os.OpenFile("sec.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: l})
	//log.Print(string(n))

	return n
}

// import private key from pem format
func importPrivateKeyfromEncryptedPEM(pemsec, password []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(pemsec)
	//log.Print(block)
	buf, _ := x509.DecryptPEMBlock(block, password)
	sec, _ := x509.ParseECPrivateKey(buf)
	//log.Print(sec)
	return sec
}

// export private key to pem format
func exportPrivateKeytoEncryptedPEM(sec *ecdsa.PrivateKey, password []byte) []byte {
	l, _ := x509.MarshalECPrivateKey(sec)
	m, _ := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", l, password, x509.PEMCipherAES256)
	n := pem.EncodeToMemory(m)
	//log.Print(string(n))

	keypem, _ := os.OpenFile("sec.Encrypted.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: l})

	return n
}

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}
