package ec

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/block27/core-zero/config"
	"github.com/block27/core-zero/helpers"
	"github.com/block27/core-zero/services/dsa"
	"github.com/block27/core-zero/services/dsa/errors"
	"github.com/block27/core-zero/services/dsa/ecdsa/encodings"

	"github.com/block27/openssl"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
)

var (
	keyPath = "ec"
)

// KeyAPI main api for defining Key behavior and functions
type KeyAPI interface {
	GetAttributes() *dsa.KeyAttributes
	Struct() *key

	Sign([]byte) ([]byte, error)
	Verify([]byte, []byte) bool

	getPrivateKey() (openssl.PrivateKey, error)
	getPublicKey() (openssl.PublicKey, error)
}

// key struct is the main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage
type key struct {
	attributes *dsa.KeyAttributes

	privateKeyPEM []byte
	publicKeyPEM []byte
}

// NewEC returns a new EC type keypair created using our rand.Reader, and using
// the OpenSSL C bindings
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
		attributes: &dsa.KeyAttributes{
			GID: 						 dsa.GenerateUUID(),
			Name:            name,
			Slug:            helpers.NewHaikunator().Haikunate(),
			KeyType:         dsa.ToString(cv, dsa.Private),
			KeyUse: 				 dsa.ToString(cv, dsa.Private),
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
	dirPath := fmt.Sprintf("%s/%s/%s", c.GetString("paths.keys"), keyPath, fp)
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
		attributes: obj,
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

// ListEC returns a list of active keys stored on the local filesystem. Of
// which are all encrypted via AES from the hardware block
func ListEC(c config.Reader) ([]KeyAPI, error) {
	files, err := ioutil.ReadDir(fmt.Sprintf("%s/ec", c.GetString("paths.keys")))
	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime().Before(files[j].ModTime())
	})

	var keys []KeyAPI

	for _, f := range files {
		_key, _err := GetEC(c, f.Name())

		if _err != nil {
			continue
		}

		keys = append(keys, _key)
	}

	return keys, nil
}

// ImportPublicEC imports an existing ECDSA key into a KeyAPI object for
// use in the Service API. Since you are importing a public Key, this will be
// an incomplete Key object.
func ImportPublicEC(c config.Reader, name string, curve string, public []byte) (KeyAPI, error) {
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty")
	}

	if curve == "" {
		return nil, fmt.Errorf("curve cannot be empty")
	}

	_, cv, _, err := dsa.GetCurve(curve)
	if err != nil {
		return nil, err
	}

	pub, err := openssl.LoadPublicKeyFromPEM(public)
	if err != nil {
		return nil, err
	}

	pem, perr := pub.MarshalPKIXPublicKeyPEM()
	if perr != nil {
		return nil, perr
	}

	// Resulting key will not be complete - create the key struct object anyways
	key := &key{
		attributes: &dsa.KeyAttributes{
			GID: 						 dsa.GenerateUUID(),
			Name:            name,
			Slug:            helpers.NewHaikunator().Haikunate(),
			KeyType:         dsa.ToString(cv, dsa.Public),
			Status:          dsa.StatusActive,
			FingerprintMD5:  encodings.BaseMD5(pem),
			FingerprintSHA:  encodings.BaseSHA256(pem),
			CreatedAt:       helpers.CreatedAtNow(),
		},
		publicKeyPEM:    pem,
	}

	// Write the entire key object to FS
	if err := key.writeToFS(c); err != nil {
		return nil, err
	}

	return key, nil
}

// writeToFS writes object serialized data and both keys to disk. Encryption for
// keys should happen here
func (k *key) writeToFS(c config.Reader) error {
	// Create the keys root directory based on it's FilePointer method
	dirPath := fmt.Sprintf("%s/%s/%s", c.GetString("paths.keys"), keyPath,
		k.attributes.FilePointer())
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
	obj, err := dsa.KAToGOB64(k.attributes)
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

// GetAttributes ...
func (k *key) GetAttributes() *dsa.KeyAttributes {
	return k.attributes
}

// Struct ...
func (k *key) Struct() *key {
	return k
}

// getPrivateKey ...
func (k *key) getPrivateKey() (openssl.PrivateKey, error) {
	key, err := openssl.LoadPrivateKeyFromPEM(k.privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// getPublicKey ...
func (k *key) getPublicKey() (openssl.PublicKey, error) {
	key, err := openssl.LoadPublicKeyFromPEM(k.publicKeyPEM)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Sign uses the OpenSSL [SignPKCS1v15] method and returns a resulting signature
func (k *key) Sign(data []byte) ([]byte, error) {
	pk, err := k.getPrivateKey()
	if err != nil {
		return nil, err
	}

	return pk.SignPKCS1v15(openssl.SHA256_Method, data)
}

// Verify checks the passed signature and returns a bool depending on verification
func (k *key) Verify(data, sig []byte) bool {
	pk, err := k.getPublicKey()
	if err != nil {
		return false
	}

	if er := pk.VerifyPKCS1v15(openssl.SHA256_Method, data, sig); er != nil {
		return false
	}

	return true
}


// PrintKeysTW prints an elaborate way to display key information... not needed,
// but nice for demos and visually displays the key randomArt via a python script
func PrintKeysTW(keys []KeyAPI) {
	stylePairs := [][]table.Style{
		{table.StyleColoredBright},
	}

	for ndx, f := range keys {
		tw := table.NewWriter()

		tw.SetTitle(f.GetAttributes().FilePointer())
		tw.AppendRows([]table.Row{
			{
				"Name",
				f.GetAttributes().Name,
			},
			{
				"Slug",
				f.GetAttributes().Slug,
			},
			{
				"Type",
				helpers.RFgB(f.GetAttributes().KeyType),
			},
			{
				"Created",
				f.GetAttributes().CreatedAt,
			},
			{
				"MD5",
				f.GetAttributes().FingerprintMD5,
			},
			{
				"SHA256",
				f.GetAttributes().FingerprintSHA,
			},
			{
				"SHA256 Visual",
				f.GetAttributes().ArtSignature(),
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

// PrintKeyTW takes an array of keys and runs them through prettyPrint function
func PrintKeyTW(k *key) {
	PrintKeysTW([]KeyAPI{k})
}
