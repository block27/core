package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"sync"
	"time"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/crypto"
	"github.com/amanelis/bespin/helpers"
	api "github.com/amanelis/bespin/services/keys/api"
	enc "github.com/amanelis/bespin/services/keys/ecdsa/encodings"
	mar "github.com/amanelis/bespin/services/keys/ecdsa/marshall"
	sig "github.com/amanelis/bespin/services/keys/ecdsa/signature"
	eer "github.com/amanelis/bespin/services/keys/errors"

	guuid "github.com/google/uuid"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"github.com/sirupsen/logrus"
)

// KeyAPI main api for defining Key behavior and functions
type KeyAPI interface {
	FilePointer() string
	Struct() *key

	getArtSignature() string
	getPrivateKey() (*ecdsa.PrivateKey, error)
	getPublicKey() (*ecdsa.PublicKey, error)

	Marshall() (string, error)
	Unmarshall(string) (KeyAPI, error)

	Sign([]byte) (*sig.Signature, error)
	Verify([]byte, *sig.Signature) bool
}

// key struct is the main type and placeholder for private keys on the system.
// These should be persisted to a flat file database storage.
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
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewECDSABlank simply returns a blank object of KeyAPI/key struct
func NewECDSABlank(c config.Reader) (KeyAPI, error) {
	return &key{}, nil
}

// NewECDSA is the main factory method for creating the ECDSA key. Quite
// complicated but what happens here is complete key generation using our
// cyrpto/rand lib
func NewECDSA(c config.Reader, name string, curve string) (KeyAPI, error) {
	// Validate the type of curve passed
	ec, ty, err := getCurve(curve)
	if err != nil {
		return nil, err
	}

	// Generate the private key with our own io.Reader
	pri, err := ecdsa.GenerateKey(ec, crypto.Reader)
	if err != nil {
		return nil, err
	}

	// Grab the public key
	pub := &pri.PublicKey

	// PEM #1 - encoding
	pemKey, pemPub, perr := enc.Encode(pri, pub)
	if perr != nil {
		return nil, perr
	}

	// Create the key struct object
	key := &key{
		GID:            api.GenerateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeyType:        fmt.Sprintf("ecdsa.PrivateKey <==> %s", ty),
		Status:         api.StatusActive,
		PublicKeyB64:   base64.StdEncoding.EncodeToString([]byte(pemPub)),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString([]byte(pemKey)),
		FingerprintMD5: enc.FingerprintMD5(pub),
		FingerprintSHA: enc.FingerprintSHA256(pub),
		CreatedAt:      time.Now(),
	}

	// Write the entire key object to FS
	if err := key.writeToFS(c, pri, pub); err != nil {
		return nil, err
	}

	key.privateKey = pri
	key.publicKey = pub

	return key, nil
}

// GetECDSA fetches a system key that lives on the file system. Return useful
// identification data aobut the key, likes its SHA256 and MD5 signatures
func GetECDSA(c config.Reader, fp string) (KeyAPI, error) {
	dirPath := fmt.Sprintf("%s/%s", c.GetString("paths.keys"), fp)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return (*key)(nil), eer.NewKeyPathError("invalid key path")
	}

	data, err := helpers.ReadFile(fmt.Sprintf("%s/obj.bin", dirPath))
	if err != nil {
		return (*key)(nil), eer.NewKeyObjtError("invalid key objt")
	}

	obj, err := keyFromGOB64(data)
	if err != nil {
		return (*key)(nil), err
	}

	return obj, nil
}

// ListECDSA returns a list of active keys stored on the local filesystem. Of
// which are all encrypted via AES from the hardware block
func ListECDSA(c config.Reader) ([]KeyAPI, error) {
	files, err := ioutil.ReadDir(c.GetString("paths.keys"))
	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime().Before(files[j].ModTime())
	})

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

// ImportPublicECDSA imports an existing ECDSA key into a KeyAPI object for
// use in the Service API. Since you are importing a public Key, this will be
// an incomplete Key object.
func ImportPublicECDSA(c config.Reader, name string, curve string, public []byte) (KeyAPI, error) {
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	if curve == "" {
		return nil, fmt.Errorf("curve cannot be empty")
	}

	_, ty, err := getCurve(curve)
	if err != nil {
		return nil, err
	}

	pub, err := mar.DecodePublicKey(public)
	if err != nil {
		return nil, err
	}

	pem, perr := enc.EncodePublic(pub)
	if perr != nil {
		return nil, perr
	}

	// Resulting key will not be complete - create the key struct object anyways
	key := &key{
		GID:            api.GenerateUUID(),
		Name:           name,
		Slug:           helpers.NewHaikunator().Haikunate(),
		KeyType:        fmt.Sprintf("ecdsa.PublicKey <==> %s", ty),
		Status:         api.StatusActive,
		PublicKeyB64:   base64.StdEncoding.EncodeToString([]byte(pem)),
		PrivateKeyB64:  "",
		FingerprintMD5: enc.FingerprintMD5(pub),
		FingerprintSHA: enc.FingerprintSHA256(pub),
		CreatedAt:      time.Now(),
	}

	// Write the entire key object to FS
	if err := key.writeToFS(c, nil, pub); err != nil {
		return nil, err
	}

	key.privateKey = nil
	key.publicKey = pub

	return key, nil
}

// FilePointer returns a string that will represent the path the key can be
// written to on the file system
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
func (k *key) Unmarshall(obj string) (KeyAPI, error) {
	d, err := keyFromGOB64(obj)
	if err != nil {
		return (KeyAPI)(nil), err
	}

	return d, nil
}

// Struct returns the full object for access to non exported fields, not sure
// about this, but fine for now... think of a better way to implement such need,
// perhaps just using attribute getters will suffice...
func (k *key) Struct() *key {
	return k
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers{R,S}. The security of the private
// key depends on the entropy of rand / which in this case we implement our own
func (k *key) Sign(data []byte) (*sig.Signature, error) {
	pri, err := k.getPrivateKey()
	if err != nil {
		return (*sig.Signature)(nil), err
	}

	r, s, err := ecdsa.Sign(crypto.Reader, pri, data)
	if err != nil {
		return (*sig.Signature)(nil), err
	}

	return &sig.Signature{
		// MD5: md5.Sum(data),
		// SHA: sha256.Sum256(data),
		R: r,
		S: s,
	}, nil
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func (k *key) Verify(hash []byte, sig *sig.Signature) bool {
	pub, err := k.getPublicKey()
	if err != nil {
		panic(err)
	}

	return ecdsa.Verify(pub, hash, sig.R, sig.S)
}

// writeToFS
func (k *key) writeToFS(c config.Reader, pri *ecdsa.PrivateKey, pub *ecdsa.PublicKey) error {
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
	if pub != nil {
		publickeyFile, err := os.Create(k.PublicKeyPath)
		if err != nil {
			return err
		}

		pubBytes, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}

		publickeyFile.Write(pubBytes)
		publickeyFile.Close()
	}

	// Private Key ---------------------------------------------------------------
	if pri != nil {
		privatekeyFile, err := os.Create(k.PrivateKeyPath)
		if err != nil {
			return err
		}

		priBytes, priErr := x509.MarshalECPrivateKey(pri)
		if priErr != nil {
			return priErr
		}

		privatekeyFile.Write(priBytes)
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
		if e := pem.Encode(pemfile, &pem.Block{
			Type:  enc.ECPrivateKey,
			Bytes: pem509,
		}); e != nil {
			return e
		}
	}

	return nil
}

// getCurve checks the string param matched and should return a valid ec curve
func getCurve(curve string) (elliptic.Curve, string, error) {
	switch curve {
	case "secp224r1": // secp224r1: NIST/SECG curve over a 224 bit prime field
		return elliptic.P224(), "secp224r1", nil
	case "prime256v1": // prime256v1: X9.62/SECG curve over a 256 bit prime field
		return elliptic.P256(), "prime256v1", nil
	case "secp384r1": // secp384r1: NIST/SECG curve over a 384 bit prime field
		return elliptic.P384(), "secp384r1", nil
	case "secp521r1": // secp521r1: NIST/SECG curve over a 521 bit prime field
		return elliptic.P521(), "secp521r1", nil
	default:
		return nil, "", fmt.Errorf("%s", helpers.RFgB("incorrect curve size passed"))
	}
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
	tempKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return (*ecdsa.PrivateKey)(nil), err
	}

	return tempKey, nil
}

// getPublicKey ...
func (k *key) getPublicKey() (*ecdsa.PublicKey, error) {
	by, err := base64.StdEncoding.DecodeString(k.PublicKeyB64)
	if err != nil {
		return (*ecdsa.PublicKey)(nil), err
	}

	blockPub, _ := pem.Decode([]byte(by))
	genericPublicKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return (*ecdsa.PublicKey)(nil), err
	}

	return genericPublicKey.(*ecdsa.PublicKey), nil
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

// PrintKeysTW prints an elaborate way to display key information... not needed,
// but nice for demos and visually displays the key randomArt via a python script
func PrintKeysTW(keys []KeyAPI) {
	stylePairs := [][]table.Style{
		{table.StyleColoredBright},
	}

	for ndx, f := range keys {
		tw := table.NewWriter()

		var pr string
		if f.Struct().PrivateKeyB64 == "" {
			pr = "... ... ... ... ... ... ... ... ... ... ... ..."
		} else {
			pr = f.Struct().PrivateKeyB64[0:47]
		}

		var pu string
		if f.Struct().PublicKeyB64 == "" {
			pu = "... ... ... ... ... ... ... ... ... ... ... ..."
		} else {
			pu = f.Struct().PublicKeyB64[0:47]
		}

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
				helpers.RFgB(f.Struct().KeyType),
			},
			{
				"Created",
				f.Struct().CreatedAt,
			},
			{
				"PrivateKey",
				pr,
			},
			{
				"PublicKey",
				pu,
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

// PrintKey is a helper function to print a key
func PrintKey(k *key, l *logrus.Logger) {
	l.Infof("Key GID: %s", helpers.MFgD(k.FilePointer()))
	l.Infof("Key MD5: %s", helpers.MFgD(k.Struct().FingerprintMD5))
	l.Infof("Key SHA: %s", helpers.MFgD(k.Struct().FingerprintSHA))
	l.Infof("Key Type: %s", helpers.RFgB(k.Struct().KeyType))
	l.Infof("Key Name: %s", helpers.YFgB(k.Struct().Name))
	l.Infof("Key Slug: %s", helpers.YFgB(k.Struct().Slug))
	l.Infof("Key Status: %s", helpers.YFgB(k.Struct().Status))
	l.Infof("Key Created: %s", helpers.YFgB(k.Struct().CreatedAt))
	l.Infof("	%s privateKey: %s......", helpers.RFgB(">"), k.Struct().PrivateKeyB64[0:64])
	l.Infof("	%s publicKey:  %s......", helpers.RFgB(">"), k.Struct().PublicKeyB64[0:64])
	l.Infof("	%s privatePemPath: %s", helpers.RFgB(">"), k.Struct().PrivatePemPath)
	l.Infof("	%s privateKeyPath: %s", helpers.RFgB(">"), k.Struct().PrivateKeyPath)
	l.Infof("	%s publicKeyPath:  %s", helpers.RFgB(">"), k.Struct().PublicKeyPath)
}
