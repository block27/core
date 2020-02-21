package ec

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/dsa"
	"github.com/amanelis/bespin/services/dsa/ecdsa/encodings"

	"github.com/spacemonkeygo/openssl"
	guuid "github.com/google/uuid"
)

// KeyAPI main api for defining Key behavior and functions
type KeyAPI interface {
	FilePointer() string
	Struct() *key

	getArtSignature() string
	getPrivateKey() (*openssl.PrivateKey, error)
	getPublicKey() (*openssl.PublicKey, error)

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

	privateKeyBytes []byte
	publicKeyBytes []byte
}

// NewEC ...
func NewEC(c config.Reader, name string, curve string) (KeyAPI, error) {
	// Validate the type of curve passed
	_, ty, ol, err := dsa.GetCurve(curve)
	if err != nil {
		return nil, err
	}

	pri, err := openssl.GenerateECKey(ol)
	if err != nil {
		return nil, err
	}

	pubEnc, err := pri.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return nil, err
	}

	priEnc, err := pri.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return nil, err
	}

	typ, terr := getType(ty, dsa.Private)
	if terr != nil {
		return nil, terr
	}

	// Create the key struct object
	key := &key{
		GID:             dsa.GenerateUUID(),
		Name:            name,
		Slug:            helpers.NewHaikunator().Haikunate(),
		KeyType:         typ,
		Status:          dsa.StatusActive,
		FingerprintMD5:  encodings.BaseMD5(pubEnc),
		FingerprintSHA:  encodings.BaseSHA256(pubEnc),
		CreatedAt:       time.Now(),

		privateKeyBytes: priEnc,
		publicKeyBytes:  pubEnc,
	}

	// Write the entire key object to FS
	if err := key.writeToFS(c, priEnc, pubEnc); err != nil {
		return nil, err
	}

	return key, nil
}

func (k *key) writeToFS(c config.Reader, pri []byte, pub []byte) error {
	// Create the keys root directory based on it's FilePointer method
	dirPath := fmt.Sprintf("%s/ecdsa/%s", c.GetString("paths.keys"), k.FilePointer())
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		os.Mkdir(dirPath, os.ModePerm)
	}

	// OBJ marshalling -----------------------------------------------------------
	objPath := fmt.Sprintf("%s/%s", dirPath, "obj.bin")
	objFile, err := os.Create(objPath)
	if err != nil {
		return err
	}
	defer objFile.Close()

	// Marshall the objects
	obj, err := keyToGOB64(k)
	if err != nil {
		return err
	}

	if _, err := helpers.WriteBinary(objPath, []byte(obj)); err != nil {
		return err
	}

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

func (k *key) getPrivateKey() (*openssl.PrivateKey, error) {
	return nil, nil
}

func (k *key) getPublicKey() (*openssl.PublicKey, error) {
	return nil, nil
}

func (k *key) Sign([]byte) ([]byte, error) {
	return nil, nil
}

func (k *key) Verify([]byte, []byte) bool {
	return false
}

// Helpers
func getType(curve string, pk string) (string, error) {
	// if pk != dsa.Private || pk != dsa.Public {
	// 	return "", fmt.Errorf("invalid pk identifier passed, should be ['public', 'private']")
	// }

	return fmt.Sprintf("ec.PrivateKey <==> %s", curve), nil
}

// keyToGOB64 takes a pointer to an existing key and return it's entire body
// object base64 encoded for storage.
func keyToGOB64(k *key) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)

	if err := e.Encode(k); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// keyFromGOB64 takes a base64 encoded string and convert that to an object. We
// need a way to handle updates here.
func keyFromGOB64(str string) (*key, error) {
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return (*key)(nil), err
	}

	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)

	var k *key

	if err = d.Decode(&k); err != nil {
		fmt.Println("failed gob Decode", err)
	}

	return k, nil
}
