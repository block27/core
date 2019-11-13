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
	ECPrivateKey = "EC PRIVATE KEY"
	ECPublicKey  = "EC PUBLIC KEY"
	SDPublicKey  = "PUBLIC KEY"
)

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
		Type:    ECPublicKey,
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
		Type:    ECPrivateKey,
		Headers: nil,
		Bytes:   l,
	}
	n := pem.EncodeToMemory(&m)

	keypem, _ := os.OpenFile("sec.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: ECPrivateKey, Bytes: l})

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

// Encode ...
func Encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: ECPrivateKey, Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: SDPublicKey, Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}

// Decode ...
func Decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

	blockPub, _ := pem.Decode([]byte(pemEncodedPub))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
	publicKey := genericPublicKey.(*ecdsa.PublicKey)

	return privateKey, publicKey
}
