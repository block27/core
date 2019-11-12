package ecdsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/amanelis/bespin/crypto"

	"golang.org/x/crypto/ssh"
)

var (
	ecPrivateKey = "EC PRIVATE KEY"
	ecPublicKey  = "EC PUBLIC KEY"
	sdPublicKey  = "PUBLIC KEY"
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
		Type:    ecPublicKey,
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
		Type:    ecPrivateKey,
		Headers: nil,
		Bytes:   l,
	}
	n := pem.EncodeToMemory(&m)

	keypem, _ := os.OpenFile("sec.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: ecPrivateKey, Bytes: l})

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
	m, _ := x509.EncryptPEMBlock(crypto.Reader, ecPrivateKey, l, password, x509.PEMCipherAES256)
	n := pem.EncodeToMemory(m)

	keypem, _ := os.OpenFile("sec.Encrypted.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keypem, &pem.Block{Type: ecPrivateKey, Bytes: l})

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
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: ecPrivateKey, Bytes: x509Encoded})

	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: sdPublicKey, Bytes: x509EncodedPub})

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
