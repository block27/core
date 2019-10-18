package crypto

import (
  "crypto/md5"
	"crypto/sha1"
	"crypto/sha256"

  "github.com/spacemonkeygo/openssl"
)

type AESCredentials struct {
  Key    []byte
  Iv     []byte
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

// DigestSHA256Sum uses SHA256 digest to create the key which is the default behaviour since OpenSSL 1.1.0c
func DigestSHA256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func NewCrypter(key []byte, iv []byte) (*Crypter, error) {
  cipher, err := openssl.GetCipherByName("aes-256-cbc")
  if err != nil {
    return nil, err
  }

  return &Crypter{key, iv, cipher}, nil
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
