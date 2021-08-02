package ec

import (
	"fmt"
	"sync"
	"time"

	"github.com/block27/core/config"
	"github.com/block27/core/helpers"
	"github.com/block27/core/services/dsa"
	"github.com/block27/core/services/dsa/ecdsa/encodings"

	guuid "github.com/google/uuid"
	"github.com/spacemonkeygo/openssl"
)

// KeyAPI main api for defining Key behavior and functions
type KeyAPI interface {
	FilePointer() string

	getArtSignature() string
	getPrivateKey() (openssl.PrivateKey, error)
	getPublicKey() (openssl.PublicKey, error)

	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) bool
}

// key struct is the main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage.
type key struct {
	sink sync.Mutex // mutex to allow clean concurrent access
	GID  guuid.UUID // guuid for crypto identification

	// Base name passed from CLI, *not indexed
	Name string

	// Slug auto generated from Haiku *not indexed
	Slug string

	// Hold the base key status, {archive, active}
	Status string

	// Basically the elliptic curve size of the key
	KeyType string

	FingerprintMD5 string // Real fingerprint in  MD5  (legacy)  of the key
	FingerprintSHA string // Real fingerprint in  SHA256  of the key

	CreatedAt time.Time

	PrivateKeyDER []byte
	PrivateKeyPEM []byte

	PublicKeyDER []byte
	PublicKeyPEM []byte
}

// NewEC ...
func NewEC(c config.Reader, name string, curve string) (KeyAPI, error) {
	// Validate the type of curve passed
	_, cv, ol, err := dsa.GetCurve(curve)
	if err != nil {
		return nil, err
	}

	typ, terr := getType(cv, dsa.Private)
	if terr != nil {
		return nil, terr
	}

	pri, err := openssl.GenerateECKey(ol)
	if err != nil {
		return nil, err
	}

	pubDer, err := pri.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil, err
	}

	pubPem, err := pri.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return nil, err
	}

	priPem, err := pri.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return nil, err
	}

	priDer, err := pri.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		return nil, err
	}

	// Create the key struct object
	key := &key{
		GID:            dsa.GenerateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeyType:        typ,
		Status:         dsa.StatusActive,
		FingerprintMD5: encodings.BaseMD5(pubPem),
		FingerprintSHA: encodings.BaseSHA256(pubPem),
		CreatedAt:      time.Now(),
		PrivateKeyDER:  priDer,
		PrivateKeyPEM:  priPem,
		PublicKeyDER:   pubDer,
		PublicKeyPEM:   pubPem,
	}

	// Write the entire key object to FS
	// if err := key.writeToFS(c, priEnc, pubEnc); err != nil {
	// 	return nil, err
	// }

	return key, nil
}

func (k *key) writeToFS(c config.Reader, pri []byte, pub []byte) error {
	return nil
}

// Struct ...
func (k *key) Struct() *key {
	return k
}

// FilePointer ...
func (k *key) FilePointer() string {
	return k.GID.String()
}

func (k *key) getArtSignature() string {
	return ""
}

func (k *key) getPrivateKey() (openssl.PrivateKey, error) {
	key, err := openssl.LoadPrivateKeyFromPEM(k.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *key) getPublicKey() (openssl.PublicKey, error) {
	return nil, nil
	// hex, err := hex.DecodeString(k.publicKey)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// key, err := openssl.LoadPublicKeyFromPEM(hex)
	// if err != nil {
	// 	return nil, err
	// }
	//
	// return key, nil
}

func (k *key) Sign([]byte) ([]byte, error) {
	return nil, nil
}

func (k *key) Verify([]byte, []byte) bool {
	return false
}

// Helpers
func getType(curve string, pk string) (string, error) {
	return fmt.Sprintf("ec.%sKey <==> %s", pk, curve), nil
}
