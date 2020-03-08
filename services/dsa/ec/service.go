package ec

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"runtime"

	"github.com/amanelis/core-zero/config"
	"github.com/amanelis/core-zero/helpers"
	"github.com/amanelis/core-zero/services/dsa"
	"github.com/amanelis/core-zero/services/dsa/errors"
	"github.com/amanelis/core-zero/services/dsa/ecdsa/encodings"

	"github.com/spacemonkeygo/openssl"
	guuid "github.com/google/uuid"
)

// KeyAPI main api for defining Key behavior and functions
type KeyAPI interface {
	GetAttributes() *dsa.KeyAttributes
	FilePointer() string
	KeyID() guuid.UUID
	Struct() *key

	getArtSignature() string
	getPrivateKey() (openssl.PrivateKey, error)
	getPublicKey() (openssl.PublicKey, error)

	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) bool
}

// key struct is the main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage.
type key struct {
	Attributes *dsa.KeyAttributes

	privateKeyPEM []byte
	publicKeyPEM []byte
}

// NewEC ...
func NewEC(c config.Reader, name string, curve string) (KeyAPI, error) {
	_, cv, ol, err := dsa.GetCurve(curve)
	if err != nil {
		return nil, err
	}

	pri, err := openssl.GenerateECKey(ol)
	if err != nil {
		return nil, err
	}

	priPemBytes, err := pri.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return nil, err
	}

	pubPemBytes, err := pri.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return nil, err
	}

	// Create the key struct object
	key := &key{
		Attributes: &dsa.KeyAttributes{
			GID: 						 dsa.GenerateUUID(),
			Name:            name,
			Slug:            helpers.NewHaikunator().Haikunate(),
			KeyType:         dsa.ToString(cv, dsa.Private),
			Status:          dsa.StatusActive,
			FingerprintMD5:  encodings.BaseMD5(pubPemBytes),
			FingerprintSHA:  encodings.BaseSHA256(pubPemBytes),
			CreatedAt:       helpers.CreatedAtNow(),
		},
		privateKeyPEM: 	 priPemBytes,
		publicKeyPEM:    pubPemBytes,
	}

	// Write the entire key object to FS
	if err := key.writeToFS(c); err != nil {
		return nil, err
	}

	return key, nil
}

// GetEC fetches a system key that lives on the file system. Return useful
// identification data aobut the key, likes its SHA256 and MD5 signatures
func GetEC(c config.Reader, fp string) (KeyAPI, error) {
	dirPath := fmt.Sprintf("%s/ec/%s", c.GetString("paths.keys"), fp)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return (*key)(nil), errors.NewKeyPathError("invalid key path")
	}

	objPath := fmt.Sprintf("%s/obj.bin", dirPath)

	if !helpers.FileExists(objPath) {
		return (*key)(nil), fmt.Errorf("missing serialized object file")
	}

	data, err := helpers.ReadFile(objPath)
	if err != nil {
		return (*key)(nil), errors.NewKeyObjtError("invalid key obj")
	}

	obj, err := dsa.KAFromGOB64(data)
	if err != nil {
		return (*key)(nil), nil
	}

	k := &key{
		Attributes: obj,
	}

	keyPath := fmt.Sprintf("%s/key.pem", dirPath)

	// Load the privateKey
	priKeyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return (*key)(nil), nil
	}

	pri, err := openssl.LoadPrivateKeyFromPEM(priKeyBytes)
	if err != nil {
		return (*key)(nil), nil
	}

	priPemBytes, err := pri.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return (*key)(nil), nil
	}

	pubPemBytes, err := pri.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return (*key)(nil), nil
	}

	k.privateKeyPEM = priPemBytes
	k.publicKeyPEM = pubPemBytes

	return k, nil
}

func (k *key) writeToFS(c config.Reader) error {
	// Create the keys root directory based on it's FilePointer method
	dirPath := fmt.Sprintf("%s/ec/%s", c.GetString("paths.keys"), k.FilePointer())
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
	obj, err := dsa.KAToGOB64(k.Attributes)
	if err != nil {
		return err
	}

	if _, err := helpers.WriteBinary(objPath, []byte(obj)); err != nil {
		return err
	}

	if k.privateKeyPEM != nil {
		priPath := fmt.Sprintf("%s/%s", dirPath, "key.pem")

		privatekeyFile, err := os.Create(priPath)
		if err != nil {
			return err
		}

		privatekeyFile.Write(k.privateKeyPEM)
		privatekeyFile.Close()
	}

	if k.publicKeyPEM != nil {
		pubPath := fmt.Sprintf("%s/%s", dirPath, "pub.pem")

		publickeyFile, err := os.Create(pubPath)
		if err != nil {
			return err
		}

		publickeyFile.Write(k.publicKeyPEM)
		publickeyFile.Close()
	}

	return nil
}

// FilePointer ...
func (k *key) FilePointer() string {
	return k.Attributes.GID.String()
}

func (k *key) GetAttributes() *dsa.KeyAttributes {
	return k.Attributes
}

// KeyID ...
func (k *key) KeyID() guuid.UUID {
	return k.Attributes.GID
}

// Struct ...
func (k *key) Struct() *key {
	return k
}

func (k *key) getArtSignature() string {
	usr, err := user.Current()
	if err != nil {
		return "--- path err ---"
	}

	var pyPath string

	if runtime.GOOS == "darwin" {
		pyPath = fmt.Sprintf("%s/.pyenv/shims/python", usr.HomeDir)
	} else if runtime.GOOS == "linux" {
		pyPath = "/usr/bin/python"
	}

	cmd := exec.Command(
		pyPath,
		"tmp/drunken_bishop.py",
		"--mode",
		"sha256",
		k.GetAttributes().FingerprintSHA,
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

func (k *key) getPrivateKey() (openssl.PrivateKey, error) {
	key, err := openssl.LoadPrivateKeyFromPEM(k.privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *key) getPublicKey() (openssl.PublicKey, error) {
	key, err := openssl.LoadPublicKeyFromPEM(k.publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *key) Sign([]byte) ([]byte, error) {
	return nil, nil
}

func (k *key) Verify([]byte, []byte) bool {
	return false
}
