package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"sync"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/amanelis/bespin/config"
	"github.com/amanelis/bespin/helpers"

	guuid "github.com/google/uuid"
)

type KeyAPI interface {
	Struct() *key
}

// key - struct, main type and placeholder for private keys on the system. These
// should be persisted to a flat file database storage.
type key struct {
	sink sync.Mutex 				// mutex to allow clean concurrent access
	GID  guuid.UUID 				`json:"gid"`	// guuid for crypto identification

	Fingerprint 	string		`json:"fingerPrint"`

	PublicKeyPath  string		`json:"publicKeyPath"`
	PrivateKeyPath string		`json:"privateKeyPath"`
	PrivatePemPath string		`json:"privatePemPath"`

	PublicKeyB64  string		`json:"publicKeyB64"`
	PrivateKeyB64 string		`json:"privateKeyB64"`
}


// NewECDSA - main factory method for creating the ECDSA key
func NewECDSA(c config.ConfigReader) (KeyAPI, error) {
	key := &key{
		GID: generateUUID(),
	}

	// Real key generation, need to eventually pipe in the rand.Reader
	// generated from PRNG and hardware devices
	sec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &sec.PublicKey

	// PEM #1 - encoding
	pKey, pPub := encode(sec, pub)

	key.PublicKeyB64 = base64.StdEncoding.EncodeToString([]byte(pPub))
	key.PrivateKeyB64 = base64.StdEncoding.EncodeToString([]byte(pKey))
	key.Fingerprint = fmt.Sprintf("%s:%s",
		pub.X.String()[0:12],
		pub.Y.String()[0:12],
	)

	// Create file paths which include the public keys curve as signature
	kDirPath := fmt.Sprintf("%s/%s", c.GetString("keys.path"), key.Fingerprint)
	if _, err := os.Stat(kDirPath); os.IsNotExist(err) {
		os.Mkdir(kDirPath, os.ModePerm)
	}

	key.PrivateKeyPath = fmt.Sprintf("%s/%s", kDirPath, "private.key")
	key.PublicKeyPath = fmt.Sprintf("%s/%s", kDirPath, "public.key")
	key.PrivatePemPath = fmt.Sprintf("%s/%s", kDirPath, "private.pem")

	// save private and public key separately
	privatekeyfile, err := os.Create(key.PrivateKeyPath)
	if err != nil {
		return nil, err
	} else {
		privatekeyencoder := gob.NewEncoder(privatekeyfile)
		privatekeyencoder.Encode(sec)
		privatekeyfile.Close()
	}

	publickeyfile, err := os.Create(key.PublicKeyPath)
	if err != nil {
		return nil, err
	} else {
		publickeyencoder := gob.NewEncoder(publickeyfile)
		publickeyencoder.Encode(pub)
		publickeyfile.Close()
	}

	// Pem for private key
	pemfile, err := os.Create(key.PrivatePemPath)
	if err != nil {
		return nil, err
	}

	// Marshall the private key to PKCS8
	pem509, _ := x509.MarshalPKCS8PrivateKey(sec)
	pemkey := &pem.Block{
		Type : "ECDSA PRIVATE KEY",
		Bytes : pem509,
	}

	e := pem.Encode(pemfile, pemkey)
	if e !=nil {
		return nil, e
	}

	// Marshall the objects
	obj, _ := json.Marshal(key)

	fmt.Printf("OBJ: %s\n", obj)

	// Write data to  file
	binFile := fmt.Sprintf("%s/%s", kDirPath, "obj.bin")
	objFile, err := os.Create(binFile)
	if err != nil {
		return nil, err
	}
	defer objFile.Close()

  if err := ioutil.WriteFile(binFile, obj, 0777); err != nil {
      return nil, err
  }

	// PEM #2
	// prpem := exportPrivateKeytoPEM(sec)
	// fmt.Printf("prpem: \n%s\n", prpem)
	//
	// pupem := exportPublicKeytoPEM(pub)
	// fmt.Printf("pupem: \n%s\n", pupem)

	return key, nil
}

// List - return all system keys
func Get(c config.ConfigReader, fp string) (*key, error) {
	kDirPath := fmt.Sprintf("%s/%s", c.GetString("keys.path"), fp)
	if _, err := os.Stat(kDirPath); os.IsNotExist(err) {
		return (*key)(nil), err
	}

	fmt.Printf("Checking dir for keys:  %s\n", kDirPath)
	data, err := helpers.ReadFile(fmt.Sprintf("%s/obj.bin", kDirPath))
	if err !=nil {
		return (*key)(nil), nil
	}

	var k1 key
	json.Unmarshal([]byte(data), &k1)


	return &k1, nil
}

// Struct - return the full object for access to non exported fields
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
