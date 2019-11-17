package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	// "crypto/md5"
	// "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"sync"
	"time"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
	"github.com/amanelis/bespin/services/keys/ecdsa/encodings"
	keys "github.com/amanelis/bespin/services/keys/lib"

	guuid "github.com/google/uuid"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"github.com/sirupsen/logrus"
)

const (
	statusActive   = "active"
	statusArchived = "archive"
)

// KeyAPI - main api for defining Key behavior and functions
type KeyAPI interface {
	FilePointer() string
	Struct() *key

	getArtSignature() string
	getPrivateKey() (*ecdsa.PrivateKey, error)
	getPublicKey() (*ecdsa.PublicKey, error)

	Marshall() (string, error)
	Unmarshall(string) (KeyAPI, error)

	Sign([]byte) (*Signature, error)
	Verify([]byte, *Signature) bool
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
	KeySize int
	KeyType string

	FingerprintMD5 string // Real fingerprint in  MD5  (legacy)  of the key
	FingerprintSHA string // Real fingerprint in  SHA256  of the key

	PrivatePemPath string // Pem PKS8 format of the private key
	PrivateKeyPath string // ECDSA path for private key
	PublicKeyPath  string // ECDSA path for public key

	PrivateKeyB64 string // B64 of private key
	PublicKeyB64  string // B64 of public key

	PrivateKeyHEX string
	PublicKeyHEX  string

	CreatedAt time.Time

	// Used as place holder converstions during Sign/Verify
	// these should probably be set to nil after use as it's
	// easy access to  the real  objects,  hence why they   aren't
	// publically accessible.  taste it.
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewECDSABlank - create a struct from a database object marshalled into obj
//
func NewECDSABlank(c config.ConfigReader) (KeyAPI, error) {
	return &key{}, nil
}

// ImportPublicECDSA - import an existing ECDSA key into a KeyAPI object for
// use in the Service API. Since you are importing a public Key, this will be
// an incomplete Key object.
func ImportPublicECDSA(name string, public []byte) (KeyAPI, error) {
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	pub, err := keys.DecodePublicKey(public)
	if err != nil {
		return nil, err
	}

	if pub.Params().BitSize == 0 {
		return nil, fmt.Errorf("key bitsize invalid, most likely incorrect pem/der format")
	}

	_, pem := encodings.Encode(nil, pub)

	// Resulting key will not be complete - create the key struct object anyways
	key := &key{
		GID:            generateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeySize:        pub.Params().BitSize,
		KeyType:        "ecdsa.PrivateKey",
		Status:         statusActive,
		PublicKeyB64:   base64.StdEncoding.EncodeToString([]byte(pem)),
		FingerprintMD5: encodings.FingerprintMD5(pub),
		FingerprintSHA: encodings.FingerprintSHA256(pub),
		CreatedAt:      time.Now(),
	}

	return key, nil
}

// NewECDSA - main factory method for creating the ECDSA key.  Quite complicated
// but what happens here is complete key generation using our cyrpto/rand lib
//
func NewECDSA(c config.ConfigReader, name string, size int) (KeyAPI, error) {
	// Real key generation, need to eventually pipe in the rand.Reader
	// generated from PRNG and hardware devices
	var curve elliptic.Curve
	switch size {
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
	pemKey, pemPub := encodings.Encode(pri, pub)

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
		FingerprintMD5: encodings.FingerprintMD5(pub),
		FingerprintSHA: encodings.FingerprintSHA256(pub),
		CreatedAt:      time.Now(),
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
		Type:  encodings.ECPrivateKey,
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

	// Write data to file
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
		return (*key)(nil), fmt.Errorf("%s", helpers.RedFgB("invalid key path"))
	}

	data, err := helpers.ReadFile(fmt.Sprintf("%s/obj.bin", dirPath))
	if err != nil {
		return (*key)(nil), fmt.Errorf("%s", helpers.RedFgB("invalid key object"))
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

// Struct - return the full object for access to non exported fields, not sure
// about this, but fine for now... think of a better way to implement such need,
// perhaps just using attribute getters will suffice...
func (k *key) Struct() *key {
	return k
}

// Sign - signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers{R,S}. The security of the private
// key depends on the entropy of rand / which in this case we implement our own
func (k *key) Sign(data []byte) (*Signature, error) {
	pri, err := k.getPrivateKey()
	if err != nil {
		return (*Signature)(nil), err
	}

	r, s, err := ecdsa.Sign(crypto.Reader, pri, data)
	if err != nil {
		return (*Signature)(nil), err
	}

	return &Signature{
		// MD5: md5.Sum(data),
		// SHA: sha256.Sum256(data),
		R: r,
		S: s,
	}, nil
}

// Verify - verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func (k *key) Verify(hash []byte, sig *Signature) bool {
	pub, err := k.getPublicKey()
	if err != nil {
		panic(err)
	}

	return ecdsa.Verify(pub, hash, sig.R, sig.S)
}

// generateUUID - generate and return a valid GUUID
func generateUUID() guuid.UUID {
	return guuid.New()
}

// getArtSignature ...
func (k *key) getArtSignature() string {
	usr, err := user.Current()
	if err != nil {
		return "--- path err ---"
	}

	cmd := exec.Command(
		fmt.Sprintf("%s/.pyenv/shims/python", usr.HomeDir),
		"tmp/drunken_bishop.py",
		"--mode",
		"sha256",
		k.FingerprintSHA,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "--- run err ---"
	}

	outStr, outErr := string(stdout.Bytes()), string(stderr.Bytes())
	if outErr != "" {
		return fmt.Sprintf("--- %s ---", outErr)
	}

	return outStr
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

// PrintKeysTW - an elaborate way to display key information... not needed, but
// nice for demos and visually displays the key randomArt via a python script
func PrintKeysTW(keys []KeyAPI) {
	stylePairs := [][]table.Style{
		{table.StyleColoredBright},
	}

	for ndx, f := range keys {
		tw := table.NewWriter()

		tw.SetTitle(f.Struct().FilePointer())
		tw.AppendRows([]table.Row{
			{
				"Name",
				f.Struct().Name,
			},
			{
				"Slug",
				f.Struct().Slug,
			},
			{
				"Type",
				helpers.RedFgB(f.Struct().KeyType),
			},
			{
				"Curve",
				helpers.RedFgB(f.Struct().KeySize),
			},
			{
				"PrivateKey",
				f.Struct().PrivateKeyB64[0:47],
			},
			{
				"PublicKey",
				f.Struct().PublicKeyB64[0:47],
			},
			{
				"MD5",
				f.Struct().FingerprintMD5,
			},
			{
				"SHA256",
				f.Struct().FingerprintSHA,
			},
			{
				"Created",
				f.Struct().CreatedAt,
			},
			{
				"SHA256 Visual",
				f.getArtSignature(),
			},
		})

		twOuter := table.NewWriter()
		tw.SetStyle(table.StyleColoredDark)
		tw.Style().Title.Align = text.AlignCenter

		for _, stylePair := range stylePairs {
			row := make(table.Row, 1)
			for idx := range stylePair {
				row[idx] = tw.Render()
			}
			twOuter.AppendRow(row)
		}

		twOuter.SetStyle(table.StyleDouble)
		twOuter.SetTitle(fmt.Sprintf("Asymmetric Key (%d)", ndx))
		twOuter.Style().Options.SeparateRows = true

		fmt.Println(twOuter.Render())
	}
}

// PrintKeyTW  ...
func PrintKeyTW(k *key) {
	PrintKeysTW([]KeyAPI{k})
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
	l.Infof("Key Created: %s", helpers.YellowFgB(k.Struct().CreatedAt))
	l.Infof("	%s privateKey: %s......", helpers.RedFgB(">"), k.Struct().PrivateKeyB64[0:64])
	l.Infof("	%s publicKey:  %s......", helpers.RedFgB(">"), k.Struct().PublicKeyB64[0:64])
	l.Infof("	%s privatePemPath: %s", helpers.RedFgB(">"), k.Struct().PrivatePemPath)
	l.Infof("	%s privateKeyPath: %s", helpers.RedFgB(">"), k.Struct().PrivateKeyPath)
	l.Infof("	%s publicKeyPath:  %s", helpers.RedFgB(">"), k.Struct().PublicKeyPath)
}
