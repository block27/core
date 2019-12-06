package eddsa

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"
	"time"

	guuid "github.com/google/uuid"
	"github.com/agl/ed25519/extra25519"
	"golang.org/x/crypto/ed25519"

	api "github.com/amanelis/bespin/services/keys/api"
	enc "github.com/amanelis/bespin/services/keys/eddsa/encodings"
	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/keys/eddsa/ecdh"
	"github.com/amanelis/bespin/utils"
)

// KeyAPI - main api for defining Key behavior and functions
type KeyAPI interface {
	FilePointer() string
	Struct() *key

	Marshall() (string, error)
	Unmarshall(string) (KeyAPI, error)
}

// key - struct, main type and placeholder for private keys on the system. These
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

	PrivatePemPath string // Pem PKS8 format of the private key
	PrivateKeyPath string // ECDSA path for private key
	PublicKeyPath  string // ECDSA path for public key

	PrivateKeyB64 string // B64 of private key
	PublicKeyB64  string // B64 of public key

	CreatedAt time.Time

	// Used as place holder converstions during Sign/Verify
	// these should probably be set to nil after use as it's
	// easy access to  the real  objects,  hence why they   aren't
	// publically accessible.  taste it.
	privateKey *ed25519.PrivateKey
	publicKey  *ed25519.PublicKey
}

// NewED25519Blank - create a struct from a database object marshalled into obj
//
func NewED25519Blank(c config.Reader) (KeyAPI, error) {
	return &key{}, nil
}

// NewEDDSA - main factory method for creating the ECDSA key.  Quite complicated
// but what happens here is complete key generation using our cyrpto/rand lib
//
func NewEDDSA(c config.Reader, name string) (KeyAPI, error) {
	pub, pri, err := ed25519.GenerateKey(crypto.Reader)
	if err != nil {
		return nil, err
	}

	// Create the key struct object
	key := &key{
		GID:            api.GenerateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeyType:        "eddsa.PrivateKey <==> ed25519",
		Status:         api.StatusActive,
		PublicKeyB64:   base64.StdEncoding.EncodeToString(pub),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(pri),
		FingerprintMD5: string(crypto.DigestMD5Sum(pub)),
		FingerprintSHA: string(crypto.DigestSHA256Sum(pub)),
		CreatedAt:      time.Now(),
	}

	// // Write the entire key object to FS
	key.writeToFS(c, &pri, &pub)


	fmt.Println(&pri)
	fmt.Println(&pub)

	return key, nil
}

// writeToFS
func (k *key) writeToFS(c config.Reader, pri *ed25519.PrivateKey, pub *ed25519.PublicKey) error {
	// Create the keys root directory based on it's FilePointer method
	dirPath := fmt.Sprintf("%s/%s", c.GetString("paths.keys"), k.FilePointer())
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		os.Mkdir(dirPath, os.ModePerm)
	}

	k.PublicKeyPath = fmt.Sprintf("%s/%s", dirPath, "public.key")
	k.PrivateKeyPath = fmt.Sprintf("%s/%s", dirPath, "private.key")
	k.PrivatePemPath = fmt.Sprintf("%s/%s", dirPath, "private.pem")

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

	// Public Key ----------------------------------------------------------------
	if pub !=  nil {
		publickeyFile, err := os.Create(k.PublicKeyPath)
		if err != nil {
			return err
		}

		publickeyencoder := gob.NewEncoder(publickeyFile)
		publickeyencoder.Encode(pub)
		publickeyFile.Close()
	}

	// Private Key ---------------------------------------------------------------
	if pri != nil {
		privatekeyFile, err := os.Create(k.PrivateKeyPath)
		if err != nil {
			return err
		}

		privatekeyencoder := gob.NewEncoder(privatekeyFile)
		privatekeyencoder.Encode(pri)
		privatekeyFile.Close()

		// Private Pem -------------------------------------------------------------
		pemfile, err := os.Create(k.PrivatePemPath)
		if err != nil {
			return err
		}

		// Marshall the private key to PKCS8
		pem509, pemErr := x509.MarshalPKCS8PrivateKey(pri)
		if pemErr != nil {
			return pemErr
		}

		// Create pem file
		if  e := pem.Encode(pemfile, &pem.Block{
			Type:  enc.EDPrivateKey,
			Bytes: pem509,
		}); e != nil {
			return e
		}
	}

	return nil
}

// Struct - return the full object for access to non exported fields, not sure
// about this, but fine for now... think of a better way to implement such need,
// perhaps just using attribute getters will suffice...
func (k *key) Struct() *key {
	return k
}

// FilePointer - return a string that will represent the path the key can be
// written to on the file system
//
func (k *key) FilePointer() string {
	return k.GID.String()
}

// Marshall ...
func (k *key) Marshall() (string, error)  {
	return "", nil
}

// Unmarshall ...
func (k *key) Unmarshall(string) (KeyAPI, error)  {
	return nil, nil
}

// keyToGOB64 - take a pointer to an existing key and return it's entire body
// object base64 encoded for storage.
func keyToGOB64(k *key) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)

	if err := e.Encode(k); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// keyFromGOB64 - take a base64 encoded string and convert that to an object. We
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


























const (
	// PublicKeySize is the size of a serialized PublicKey in bytes (32 bytes).
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a serialized PrivateKey in bytes (64 bytes).
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a serialized Signature in bytes (64 bytes).
	SignatureSize = ed25519.SignatureSize

	keyType = "ed25519"
)

var errInvalidKey = errors.New("eddsa: invalid key")

// PublicKey is a EdDSA public key.
type PublicKey struct {
	pubKey    ed25519.PublicKey
	priKey 		ed25519.PrivateKey
	b64String string
}

// PrivateKey is a EdDSA private key.
type PrivateKey struct {
	pubKey  PublicKey
	privKey ed25519.PrivateKey
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (k *PublicKey) InternalPtr() *ed25519.PublicKey {
	return &k.pubKey
}

// Bytes returns the raw public key.
func (k *PublicKey) Bytes() []byte {
	return k.pubKey
}

// Identity returns the key's identity, in this case it's our
// public key in bytes.
func (k *PublicKey) Identity() []byte {
	return k.Bytes()
}

// ByteArray returns the raw public key as an array suitable for use as a map
// key.
func (k *PublicKey) ByteArray() [PublicKeySize]byte {
	var pk [PublicKeySize]byte
	copy(pk[:], k.pubKey[:])
	return pk
}

// FromBytes deserializes the byte slice b into the PublicKey.
func (k *PublicKey) FromBytes(b []byte) error {
	if len(b) != PublicKeySize {
		return errInvalidKey
	}

	k.pubKey = make([]byte, PublicKeySize)
	copy(k.pubKey, b)
	k.rebuildB64String()
	return nil
}

// MarshalBinary implements the BinaryMarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// MarshalText implements the TextMarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k.Bytes())), nil
}

// UnmarshalText implements the TextUnmarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PublicKey) UnmarshalText(data []byte) error {
	return k.FromString(string(data))
}

// FromString deserializes the string s into the PublicKey.
func (k *PublicKey) FromString(s string) error {
	// Try Base16 first, a correct Base64 key will never be mis-identified.
	if raw, err := hex.DecodeString(s); err == nil {
		return k.FromBytes(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return k.FromBytes(raw)
	}
	return fmt.Errorf("eddsa: key is neither Base16 nor Base64")
}

// ToPEMFile writes out the PublicKey to a PEM file at path f.
func (k *PublicKey) ToPEMFile(f string) error {
	const keyType = "ED25519 PUBLIC KEY"

	if utils.CtIsZero(k.pubKey[:]) {
		return fmt.Errorf("eddsa: attempted to serialize scrubbed key")
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: k.Bytes(),
	}
	return ioutil.WriteFile(f, pem.EncodeToMemory(blk), 0600)
}

// ToECDH converts the PublicKey to the corresponding ecdh.PublicKey.
func (k *PublicKey) ToECDH() *ecdh.PublicKey {
	var dhBytes, dsaBytes [32]byte
	copy(dsaBytes[:], k.Bytes())
	defer utils.ExplicitBzero(dsaBytes[:])
	extra25519.PublicKeyToCurve25519(&dhBytes, &dsaBytes)
	defer utils.ExplicitBzero(dhBytes[:])
	r := new(ecdh.PublicKey)
	r.FromBytes(dhBytes[:])
	return r
}

// Reset clears the PublicKey structure such that no sensitive data is left in
// memory.  PublicKeys, despite being public may be considered sensitive in
// certain contexts (eg: if used once in path selection).
func (k *PublicKey) Reset() {
	utils.ExplicitBzero(k.pubKey)
	k.b64String = "[scrubbed]"
}

// Verify returns true iff the signature sig is valid for the message msg.
func (k *PublicKey) Verify(sig, msg []byte) bool {
	return ed25519.Verify(k.pubKey, msg, sig)
}

// String returns the public key as a base64 encoded string.
func (k *PublicKey) String() string {
	return k.b64String
}

func (k *PublicKey) rebuildB64String() {
	k.b64String = base64.StdEncoding.EncodeToString(k.Bytes())
}

// Equal returns true iff the public key is byte for byte identical.
func (k *PublicKey) Equal(cmp *PublicKey) bool {
	return subtle.ConstantTimeCompare(k.pubKey[:], cmp.pubKey[:]) == 1
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (k *PrivateKey) InternalPtr() *ed25519.PrivateKey {
	return &k.privKey
}

// FromBytes deserializes the byte slice b into the PrivateKey.
func (k *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeySize {
		return errInvalidKey
	}

	k.privKey = make([]byte, PrivateKeySize)
	copy(k.privKey, b)
	k.pubKey.pubKey = k.privKey.Public().(ed25519.PublicKey)
	k.pubKey.rebuildB64String()
	return nil
}

// Bytes returns the raw private key.
func (k *PrivateKey) Bytes() []byte {
	return k.privKey
}

// MarshalBinary implements the BinaryMarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PrivateKey) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

// UnmarshalBinary implements the BinaryUnmarshaler interface
// defined in https://golang.org/pkg/encoding/
func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	return k.FromBytes(data)
}

// Identity returns the key's identity, in this case it's our
// public key in bytes.
func (k *PrivateKey) Identity() []byte {
	return k.PublicKey().Bytes()
}

// KeyType returns the key type string,
// in this case the constant variable
// whose value is "ed25519".
func (k *PrivateKey) KeyType() string {
	return keyType
}

// ToECDH converts the PrivateKey to the corresponding ecdh.PrivateKey.
func (k *PrivateKey) ToECDH() *ecdh.PrivateKey {
	var dsaBytes [64]byte
	defer utils.ExplicitBzero(dsaBytes[:])
	copy(dsaBytes[:], k.Bytes())

	var dhBytes [32]byte
	extra25519.PrivateKeyToCurve25519(&dhBytes, &dsaBytes)
	defer utils.ExplicitBzero(dhBytes[:])

	r := new(ecdh.PrivateKey)
	r.FromBytes(dhBytes[:])
	return r
}

// Reset clears the PrivateKey structure such that no sensitive data is left
// in memory.
func (k *PrivateKey) Reset() {
	k.pubKey.Reset()
	utils.ExplicitBzero(k.privKey)
}

// PublicKey returns the PublicKey corresponding to the PrivateKey.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &k.pubKey
}

// Sign signs the message msg with the PrivateKey and returns the signature.
func (k *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(k.privKey, msg)
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, error) {
	pubKey, privKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}

	k := new(PrivateKey)
	k.privKey = privKey
	k.pubKey.pubKey = pubKey
	k.pubKey.rebuildB64String()
	return k, nil
}

// Load loads a new PrivateKey from the PEM encoded file privFile, optionally
// creating and saving a PrivateKey instead if an entropy source is provided.
// If pubFile is specified and a key has been created, the corresponding
// PublicKey will be written to pubFile in PEM format.
func Load(privFile, pubFile string, r io.Reader) (*PrivateKey, error) {
	const keyType = "ED25519 PRIVATE KEY"

	if buf, err := ioutil.ReadFile(privFile); err == nil {
		defer utils.ExplicitBzero(buf)
		blk, rest := pem.Decode(buf)
		defer utils.ExplicitBzero(blk.Bytes)
		if len(rest) != 0 {
			return nil, fmt.Errorf("trailing garbage after PEM encoded private key")
		}
		if blk.Type != keyType {
			return nil, fmt.Errorf("invalid PEM Type: '%v'", blk.Type)
		}
		k := new(PrivateKey)
		return k, k.FromBytes(blk.Bytes)
	} else if !os.IsNotExist(err) || r == nil {
		return nil, err
	}

	k, err := NewKeypair(r)
	if err != nil {
		return nil, err
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: k.Bytes(),
	}
	if err = ioutil.WriteFile(privFile, pem.EncodeToMemory(blk), 0600); err != nil {
		return nil, err
	}
	if pubFile != "" {
		err = k.PublicKey().ToPEMFile(pubFile)
	}
	return k, err
}
