package encodings

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	"github.com/amanelis/bespin/crypto"
	"golang.org/x/crypto/ssh"
)

var (
	// ECPrivateKey ...
	ECPrivateKey = "EC PRIVATE KEY"

	// ECPublicKey ...
	ECPublicKey  = "EC PUBLIC KEY"

	// SDPublicKey ...
	SDPublicKey  = "PUBLIC KEY"
)

// ImportPublicKeyfromPEM ...
func ImportPublicKeyfromPEM(pempub []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pempub)
	objct, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return objct.(*ecdsa.PublicKey), nil
}

// ExportPublicKeytoPEM ...
func ExportPublicKeytoPEM(pub *ecdsa.PublicKey) ([]byte, error) {
	b, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return nil, e
	}

	c := pem.Block{
		Type:    ECPublicKey,
		Headers: nil,
		Bytes:   b,
	}

	return pem.EncodeToMemory(&c), nil
}

// ImportPrivateKeyfromPEM ...
func ImportPrivateKeyfromPEM(pemsec []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemsec)
	sec, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return sec, nil
}

// ExportPrivateKeytoPEM ...
func ExportPrivateKeytoPEM(sec *ecdsa.PrivateKey) ([]byte, error) {
	l, e := x509.MarshalECPrivateKey(sec)
	if e != nil {
		return nil, e
	}

	m := pem.Block{
		Type:    ECPrivateKey,
		Headers: nil,
		Bytes:   l,
	}

	return pem.EncodeToMemory(&m), nil
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
	m, _ := x509.EncryptPEMBlock(crypto.Reader, ECPrivateKey, l, password, x509.PEMCipherAES256)
	n := pem.EncodeToMemory(m)

	keypem, _ := os.OpenFile("sec.Encrypted.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: ECPrivateKey, Bytes: l})

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

// BaseMD5 ...
func BaseMD5(data []byte) string {
	md5sum := md5.Sum(data)
	hexarray := make([]string, len(md5sum))

	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}

	return strings.Join(hexarray, ":")
}

// BaseSHA256 ...
func BaseSHA256(data []byte) string {
	sha256sum := sha256.Sum256(data)
	return base64.RawStdEncoding.EncodeToString(sha256sum[:])
}

// FingerprintMD5 - returns the user presentation of the key's fingerprint
// as described by RFC 4716 section 4.
func FingerprintMD5(publicKey *ecdsa.PublicKey) string {
	md5sum := md5.Sum(ssh.Marshal(publicKey))
	hexarray := make([]string, len(md5sum))

	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}

	return strings.Join(hexarray, ":")
}

// FingerprintSHA256 - returns the user presentation of the key's fingerprint as
// unpadded base64 encoded sha256 hash. This format was introduced from
// OpenSSH 6.8.
// https://www.openssh.com/txt/release-6.8
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func FingerprintSHA256(publicKey *ecdsa.PublicKey) string {
	sha256sum := sha256.Sum256(ssh.Marshal(publicKey))
	return base64.RawStdEncoding.EncodeToString(sha256sum[:])
}


// EncodePublic ...
func EncodePublic(publicKey *ecdsa.PublicKey) (string, error) {
	x509EncodedPub, e := x509.MarshalPKIXPublicKey(publicKey)
	if e != nil {
		return "", e
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{
		Type: SDPublicKey,
		Bytes: x509EncodedPub,
	})

	return string(pemEncodedPub), nil
}

// EncodePrivate ...
func EncodePrivate(privateKey *ecdsa.PrivateKey) (string, error) {
	x509Encoded, e := x509.MarshalECPrivateKey(privateKey)
	if e != nil {
		return "", e
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type: ECPrivateKey,
		Bytes: x509Encoded,
	})

	return string(pemEncoded), nil
}

// Encode ...
func Encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string, error) {
	if privateKey == nil {
		privateKey = &ecdsa.PrivateKey{}
	}

	if publicKey == nil {
		publicKey = &ecdsa.PublicKey{}
	}

	x509Encoded, e := x509.MarshalECPrivateKey(privateKey)
	if e != nil {
		return "", "", e
	}

	pemEncoded := pem.EncodeToMemory(&pem.Block{
		Type: ECPrivateKey,
		Bytes: x509Encoded,
	})

	x509EncodedPub, e := x509.MarshalPKIXPublicKey(publicKey)
	if e != nil {
		return "", "", e
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{
		Type: SDPublicKey,
		Bytes: x509EncodedPub,
	})

	return string(pemEncoded), string(pemEncodedPub), nil
}

// Decode ...
func Decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	privateKey, e := x509.ParseECPrivateKey(block.Bytes)
	if e != nil {
		return nil, nil, e
	}

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	genericPublicKey, e := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if e != nil {
		return nil, nil, e
	}

	return privateKey, genericPublicKey.(*ecdsa.PublicKey), nil
}
