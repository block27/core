package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"

	"github.com/awnumar/memguard"
	"github.com/block27/openssl"
)

type AESCredentials struct {
	key []byte
	iv  []byte
}

type AESCredentialsEnclave struct {
	key *memguard.Enclave
	iv  *memguard.Enclave
}

type Crypter struct {
	key    []byte
	iv     []byte
	cipher *openssl.Cipher
}

// DigestFunc are functions to create a key from the passphrase
type DigestFunc func([]byte) []byte

// DigestMD5Sum uses the (deprecated) pre-OpenSSL 1.1.0c MD5 digest to create the key
func DigestMD5Sum(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// DigestSHA1Sum uses SHA1 digest to create the key
func DigestSHA1Sum(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// DigestSHA256Sum uses SHA256 digest to create the key which is the default
// behaviour since OpenSSL 1.1.0c
func DigestSHA256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// NewCrypter AES 256 CBC mode encryption object
func NewCrypter(key []byte, iv []byte) (*Crypter, error) {
	cipher, err := openssl.GetCipherByName("aes-256-cbc")
	if err != nil {
		return nil, err
	}

	return &Crypter{key, iv, cipher}, nil
}

// NewAESCredentials returns an AESCredentials object
func NewAESCredentials(key []byte, iv []byte) (*AESCredentials, error) {
	if len(string(key)) != 32 {
		return nil, errors.New("Key is of invalid length / required 32 bytes")
	}

	if len(string(iv)) != 16 {
		return nil, errors.New("Iv is of invalid length / required 16 bytes")
	}

	return &AESCredentials{key, iv}, nil
}

// NewAESCredentialsEnclave takes input and returns encrypted enclave for holding
// of the Struct
func NewAESCredentialsEnclave(key *memguard.Enclave, iv *memguard.Enclave) (*AESCredentialsEnclave, error) {
	k, err := key.Open()
	if err != nil {
		memguard.SafePanic(err)
	}

	i, err := iv.Open()
	if err != nil {
		memguard.SafePanic(err)
	}

	k.Melt()
	i.Melt()

	if len(string(k.Bytes())) != 32 {
		return nil, errors.New("Key is of invalid length / required 32 bytes")
	}

	if len(string(i.Bytes())) != 16 {
		return nil, errors.New("Iv is of invalid length / required 16 bytes")
	}

	return &AESCredentialsEnclave{
		k.Seal(),
		i.Seal(),
	},  nil
}

func (c *AESCredentials) Key() []byte {
	return c.key
}

func (c *AESCredentials) Iv() []byte {
	return c.iv
}

func (c *AESCredentialsEnclave) Key() *memguard.Enclave {
	return c.key
}

func (c *AESCredentialsEnclave) Iv() *memguard.Enclave {
	return c.iv
}

func (c *Crypter) Encrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewEncryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.EncryptUpdate(input)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.EncryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}

func (c *Crypter) Decrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewDecryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.DecryptUpdate(input)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.DecryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}
