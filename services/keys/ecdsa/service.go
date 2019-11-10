package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"

	"golang.org/x/crypto/ssh"

	guuid "github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const (
	statusActive   = "active"
	statusArchived = "archive"
)

// KeyAPI ...
//
type KeyAPI interface {
	FilePointer() string
	Struct() *key

	getPrivateKey() (*ecdsa.PrivateKey, error)
	getPublicKey() (*ecdsa.PublicKey, error)

	Marshall() (string, error)
	Unmarshall(string) (KeyAPI, error)

	Sign([]byte) (*ecdsaSignature, error)
	Verify([]byte, *ecdsaSignature) bool
}

// key - struct, main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage.
//
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
	KeySize int
	KeyType string

	FingerprintMD5 string // Real fingerprint in  MD5  (legacy)  of the key
	FingerprintSHA string // Real fingerprint in  SHA256  of the key

	PrivatePemPath string // Pem PKS8 format of the private key
	PrivateKeyPath string // ECDSA path for private key
	PublicKeyPath  string // ECDSA path for public key

	PrivateKeyB64 string // B64 of private key
	PublicKeyB64  string // B64 of public key

	// Used as place holder converstions during Sign/Verify
	// these should probably be set to nil after use as it's
	// easy access to  the real  objects,  hence why they   aren't
	// publically accessible.  taste it.
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// ecdsaSignature - just used to hold a signature and pass around a bit nicer
//
type ecdsaSignature struct {
	// Standard resulting signature values
	R, S *big.Int

	// MD5/SHA for continuity purposes down the road.
	SHA [32]byte
	MD5 [16]byte
}

// NewECDSABlank - create a struct from a database object marshalled into obj
//
func NewECDSABlank(c config.ConfigReader) (KeyAPI, error) {
	return &key{}, nil
}

// NewECDSA - main factory method for creating the ECDSA key.  Quite complicated
// but what happens here is complete key generation using our cyrpto/rand lib
//
func NewECDSA(c config.ConfigReader, name string, size int) (KeyAPI, error) {
	// Real key generation, need to eventually pipe in the rand.Reader
	// generated from PRNG and hardware devices
	var curve elliptic.Curve

	// Binary 192, 224, 256, 384, and 521
	// Prime 163, 233, 283, 409, and 571
	switch size {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%s", helpers.RedFgB("incorrect curve size passed"))
	}

	pri, err := ecdsa.GenerateKey(curve, crypto.Reader)
	if err != nil {
		return nil, err
	}

	// Grab the public key
	pub := &pri.PublicKey

	// PEM #1 - encoding
	pemKey, pemPub := encode(pri, pub)

	// Create the key struct object
	key := &key{
		GID:            generateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeySize:        pri.Params().BitSize,
		KeyType:        "ecdsa.PrivateKey",
		Status:         statusActive,
		PublicKeyB64:   base64.StdEncoding.EncodeToString([]byte(pemPub)),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString([]byte(pemKey)),
		FingerprintMD5: fingerprintMD5(pub),
		FingerprintSHA: fingerprintSHA256(pub),
	}

	// Create file paths which include the public keys curve as signature
	dirPath := fmt.Sprintf("%s/%s", c.GetString("paths.keys"), key.FilePointer())
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		os.Mkdir(dirPath, os.ModePerm)
	}

	key.PrivateKeyPath = fmt.Sprintf("%s/%s", dirPath, "private.key")
	key.PublicKeyPath = fmt.Sprintf("%s/%s", dirPath, "public.key")
	key.PrivatePemPath = fmt.Sprintf("%s/%s", dirPath, "private.pem")

	// save private and public key separately
	privatekeyFile, err := os.Create(key.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	privatekeyencoder := gob.NewEncoder(privatekeyFile)
	privatekeyencoder.Encode(pri)
	privatekeyFile.Close()

	publickeyFile, err := os.Create(key.PublicKeyPath)
	if err != nil {
		return nil, err
	}

	publickeyencoder := gob.NewEncoder(publickeyFile)
	publickeyencoder.Encode(pub)
	publickeyFile.Close()

	// Pem for private key
	pemfile, err := os.Create(key.PrivatePemPath)
	if err != nil {
		return nil, err
	}

	// Marshall the private key to PKCS8
	pem509, pemErr := x509.MarshalPKCS8PrivateKey(pri)
	if pemErr != nil {
		return nil, pemErr
	}

	pemkey := &pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: pem509,
	}

	// Create pem file
	e := pem.Encode(pemfile, pemkey)
	if e != nil {
		return nil, e
	}

	// Marshall the objects
	obj, err := keyToGOB64(key)
	if err != nil {
		return nil, err
	}

	// Write data to  file
	binFile := fmt.Sprintf("%s/%s", dirPath, "obj.bin")
	objFile, err := os.Create(binFile)
	if err != nil {
		return nil, err
	}
	defer objFile.Close()

	if err := ioutil.WriteFile(binFile, []byte(obj), 0777); err != nil {
		return nil, err
	}

	return key, nil
}

// GetECDSA - fetch a system key that lives on the file system. Return useful
// identification data aobut the key, likes its SHA256 and MD5 signatures
//
func GetECDSA(c config.ConfigReader, fp string) (KeyAPI, error) {
	dirPath := fmt.Sprintf("%s/%s", c.GetString("paths.keys"), fp)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return (*key)(nil), err
	}

	data, err := helpers.ReadFile(fmt.Sprintf("%s/obj.bin", dirPath))
	if err != nil {
		return (*key)(nil), err
	}

	obj, err := keyFromGOB64(data)
	if err != nil {
		return (*key)(nil), err
	}

	return obj, nil
}

// ListECDSA - returns a list of active keys stored on the local filesystem. Of
// which are all encrypted via AES from the hardware block
//
func ListECDSA(c config.ConfigReader) ([]KeyAPI, error) {
	files, err := ioutil.ReadDir(c.GetString("paths.keys"))
	if err != nil {
		return nil, err
	}

	var keys []KeyAPI

	for _, f := range files {
		_key, _err := GetECDSA(c, f.Name())
		if _err != nil {
			return nil, _err
		}

		keys = append(keys, _key)
	}

	return keys, nil
}

// FilePointer - return a string that will represent the path the key can be
// written to on the file system
//
func (k *key) FilePointer() string {
	return k.GID.String()
}

// Marshall ...
func (k *key) Marshall() (string, error) {
	d, err := keyToGOB64(k)
	if err != nil {
		return "", err
	}

	return d, nil
}

// Unmarshall ...
//
func (k *key) Unmarshall(obj string) (KeyAPI, error) {
	d, err := keyFromGOB64(obj)
	if err != nil {
		return (KeyAPI)(nil), err
	}

	return d, nil
}

// Sign - signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
//
func (k *key) Sign(data []byte) (*ecdsaSignature, error) {
	pKey, err := k.getPrivateKey()
	if err != nil {
		return (*ecdsaSignature)(nil), err
	}

	r, s, err := ecdsa.Sign(crypto.Reader, pKey, data)
	if err != nil {
		return (*ecdsaSignature)(nil), err
	}

	return &ecdsaSignature{
		R:   r,
		S:   s,
		MD5: md5.Sum(data),
		SHA: sha256.Sum256(data),
	}, nil
}

// Verify - verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
//
func (k *key) Verify(hash []byte, sig *ecdsaSignature) bool {
	pub, err := k.getPublicKey()
	if err != nil {
		panic(err)
	}

	return ecdsa.Verify(pub, hash, sig.R, sig.S)
}

// Struct - return the full object for access to non exported fields, not sure
// about this, but fine for now... think of a better way to implement such need,
// perhaps just using attribute getters will suffice...
func (k *key) Struct() *key {
	return k
}

// getPrivateKey ...
func (k *key) getPrivateKey() (*ecdsa.PrivateKey, error) {
	by, err := base64.StdEncoding.DecodeString(k.PrivateKeyB64)
	if err != nil {
		return (*ecdsa.PrivateKey)(nil), err
	}

	block, _ := pem.Decode([]byte(by))
	x509Encoded := block.Bytes
	tempKey, _ := x509.ParseECPrivateKey(x509Encoded)

	return tempKey, nil
}

// getPublicKey ...
func (k *key) getPublicKey() (*ecdsa.PublicKey, error) {
	by, err := base64.StdEncoding.DecodeString(k.PublicKeyB64)
	if err != nil {
		return (*ecdsa.PublicKey)(nil), err
	}

	blockPub, _ := pem.Decode([]byte(by))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return publicKey, nil
}

// generateUUID - generate and return a valid GUUID
func generateUUID() guuid.UUID {
	return guuid.New()
}

/// importPublicKeyfromPEM ...
func importPublicKeyfromPEM(pempub []byte) *ecdsa.PublicKey {
	block, _ := pem.Decode(pempub)
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	pub := pubInterface.(*ecdsa.PublicKey)
	return pub
}

// exportPublicKeytoPEM ...
func exportPublicKeytoPEM(pub *ecdsa.PublicKey) []byte {
	b, _ := x509.MarshalPKIXPublicKey(pub)
	c := pem.Block{
		Type:    "EC PUBLIC KEY",
		Headers: nil,
		Bytes:   b,
	}

	return pem.EncodeToMemory(&c)
}

// importPrivateKeyfromPEM ...
func importPrivateKeyfromPEM(pemsec []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(pemsec)
	sec, _ := x509.ParseECPrivateKey(block.Bytes)
	return sec
}

// exportPrivateKeytoPEM ...
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

	return n
}

// importPrivateKeyfromEncryptedPEM ...
func importPrivateKeyfromEncryptedPEM(pemsec, password []byte) *ecdsa.PrivateKey {
	block, _ := pem.Decode(pemsec)
	buf, _ := x509.DecryptPEMBlock(block, password)
	sec, _ := x509.ParseECPrivateKey(buf)
	return sec
}

// exportPrivateKeytoEncryptedPEM ...
func exportPrivateKeytoEncryptedPEM(sec *ecdsa.PrivateKey, password []byte) []byte {
	l, _ := x509.MarshalECPrivateKey(sec)
	m, _ := x509.EncryptPEMBlock(crypto.Reader, "EC PRIVATE KEY", l, password, x509.PEMCipherAES256)
	n := pem.EncodeToMemory(m)

	keypem, _ := os.OpenFile("sec.Encrypted.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: "EC PRIVATE KEY", Bytes: l})

	return n
}

// Fingerprinting
// -----------------------------------------------------------------------------
// ssh-keygen -l -E md5 -f ~/.ssh/id_rsa.pub
// 2048 MD5:44:91:e0:e3:64:1e:38:6e:24:7e:40:09:a3:42:2f:84 shaman@shaman.local (RSA)
// ssh-keygen -l -v -f ~/.ssh/id_rsa.pub
// 2048 SHA256:JCBJ8wQkMsKMxbtAWGeUgXydoo7JCiVOv+gG2luFt54 shaman@shaman.local
//
// awk '{print $2}' ~/.ssh/id_rsa.pub | base64 -D | sha256sum -b | sed 's/ .*$//' | xxd -r -p | base64
// JCBJ8wQkMsKMxbtAWGeUgXydoo7JCiVOv+gG2luFt54=
// -----------------------------------------------------------------------------

// fingerprintMD5 - returns the user presentation of the key's fingerprint
// as described by RFC 4716 section 4.
func fingerprintMD5(publicKey *ecdsa.PublicKey) string {
	md5sum := md5.Sum(ssh.Marshal(publicKey))
	hexarray := make([]string, len(md5sum))

	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}

	return strings.Join(hexarray, ":")
}

// fingerprintSHA256 - returns the user presentation of the key's fingerprint as
// unpadded base64 encoded sha256 hash. This format was introduced from
// OpenSSH 6.8.
// https://www.openssh.com/txt/release-6.8
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func fingerprintSHA256(publicKey *ecdsa.PublicKey) string {
	sha256sum := sha256.Sum256(ssh.Marshal(publicKey))
	return base64.RawStdEncoding.EncodeToString(sha256sum[:])
}

// encode ...
func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

// decode ...
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

// keyToGOB64 ...
func keyToGOB64(k *key) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)

	if err := e.Encode(k); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// keyFromGOB64 ...
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
		fmt.Println(`failed gob Decode`, err)
	}

	return k, nil
}

// PrintKey - helper function to print a key
func PrintKey(k *key, l *logrus.Logger) {
	l.Infof("Key GID: %s", helpers.MagentaFgD(k.FilePointer()))
	l.Infof("Key MD5: %s", helpers.MagentaFgD(k.Struct().FingerprintMD5))
	l.Infof("Key SHA: %s", helpers.MagentaFgD(k.Struct().FingerprintSHA))
	l.Infof("Key Size: %s", helpers.RedFgB(k.Struct().KeySize))
	l.Infof("Key Type: %s", helpers.RedFgB(k.Struct().KeyType))
	l.Infof("Key Name: %s", helpers.YellowFgB(k.Struct().Name))
	l.Infof("Key Slug: %s", helpers.YellowFgB(k.Struct().Slug))
	l.Infof("Key Status: %s", helpers.YellowFgB(k.Struct().Status))
	l.Infof("	%s privateKey: %s......", helpers.RedFgB(">"), k.Struct().PrivateKeyB64[0:64])
	l.Infof("	%s publicKey:  %s......", helpers.RedFgB(">"), k.Struct().PublicKeyB64[0:64])
	l.Infof("	%s privatePemPath: %s", helpers.RedFgB(">"), k.Struct().PrivatePemPath)
	l.Infof("	%s privateKeyPath: %s", helpers.RedFgB(">"), k.Struct().PrivateKeyPath)
	l.Infof("	%s publicKeyPath:  %s", helpers.RedFgB(">"), k.Struct().PublicKeyPath)
}
