package encodings

import (
	"testing"

	"github.com/amanelis/core-zero/helpers"
)

// A keypair for NIST P-256 / secp256r1
// Generated using:
//   openssl ecparam -genkey -name prime256v1 -outform PEM
var pemECPrivateKeyP256 = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOI+EZsjyN3jvWJI/KDihFmqTuDpUe/if6f/pgGTBta/oAoGCCqGSM49
AwEHoUQDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvXnFUSTwqQFo5gbfIlP+gvEYba
+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END EC PRIVATE KEY-----
`

var pemECPublicKeyP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhhObKJ1r1PcUw+3REd/TbmSZnDvX
nFUSTwqQFo5gbfIlP+gvEYba+Rxj2hhqjfzqxIleRK40IRyEi3fJM/8Qhg==
-----END PUBLIC KEY-----
`

// A keypair for NIST P-384 / secp384r1
// Generated using:
//   openssl ecparam -genkey -name secp384r1 -outform PEM
var pemECPrivateKeyP384 = `-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAhA0YPVL1kimIy+FAqzUAtmR3It2Yjv2I++YpcC4oX7wGuEWcWKBYE
oOjj7wG/memgBwYFK4EEACKhZANiAAQub8xaaCTTW5rCHJCqUddIXpvq/TxdwViH
+tPEQQlJAJciXStM/aNLYA7Q1K1zMjYyzKSWz5kAh/+x4rXQ9Hlm3VAwCQDVVSjP
bfiNOXKOWfmyrGyQ7fQfs+ro1lmjLjs=
-----END EC PRIVATE KEY-----
`

var pemECPublicKeyP384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELm/MWmgk01uawhyQqlHXSF6b6v08XcFY
h/rTxEEJSQCXIl0rTP2jS2AO0NStczI2Msykls+ZAIf/seK10PR5Zt1QMAkA1VUo
z234jTlyjln5sqxskO30H7Pq6NZZoy47
-----END PUBLIC KEY-----
`

var pemEd25519Key = `
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----
`

var garbagePEM = `-----BEGIN GARBAGE-----
TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=
-----END GARBAGE-----
`

var HEXsecp256r1Key = `
5b526eb80f43d5426ea818f0df2f1426f76a0b1a47eecf8e850cbcdf48b22956
`

var HEXsecp256r1PublicKey = `
0473f2bafac5770a50c74c65e9aaf1e08c504b3d0c68863ed42306b4971b6a5c3da5f6fea24b36589162f3dba82572a157ff8b7943d7a0899a89c332b4793b95a5
`

func TestImportPublicKeyfromPEM(t *testing.T) {
	// Valid
	key, err := ImportPublicKeyfromPEM([]byte(pemECPublicKeyP384))
	if err != nil {
		t.Fail()
	}

	if key == nil || key.Params().BitSize != 384 {
		t.Fail()
	}

	// Invalid
	if _, err := ImportPublicKeyfromPEM([]byte(garbagePEM)); err == nil {
		t.Fail()
	}
}

func TestExportPublicKeytoPEM(t *testing.T) {
	key, err := ImportPublicKeyfromPEM([]byte(pemECPublicKeyP384))
	if err != nil {
		t.Fail()
	}

	// Valid
	res, err := ExportPublicKeytoPEM(key)
	if err != nil {
		t.Fail()
	}

	if res == nil {
		t.Fail()
	}
}

func TestImportPrivateKeyfromPEM(t *testing.T) {
	// path := "../../../../data/keys/ecdsa/256-privkey.pem"
	path := "../../../../data/keys/ecdsa/prime256v1-privkey.pem"

	file, err := helpers.NewFile(path)
	if err != nil {
		t.Fail()
	}

	res, err := ImportPrivateKeyfromPEM(file.GetBody())
	if err != nil {
		t.Log(err)
	}

	if res == nil || res.Params().BitSize != 256 {
		t.Fail()
	}

	// res1, err := ImportPrivateKeyfromPEM([]byte(pemECPrivateKeyP384))
	// if err != nil {
	// 	t.Log(err)
	// 	t.Fail()
	// }
	//
	// if res1 == nil || res1.Params().BitSize != 384 {
	// 	t.Fail()
	// }
}

func TestExportPrivateKeytoPEM(t *testing.T) {
}

func TestFingerprintMD5(t *testing.T) {
	key, err := ImportPublicKeyfromPEM([]byte(pemECPublicKeyP384))
	if err != nil {
		t.Fail()
	}

	if FingerprintMD5(key) != "d9:76:a7:39:bc:4f:56:70:64:67:e7:3b:51:5f:b5:45" {
		t.Fail()
	}
}

func TestFingerprintSHA256(t *testing.T) {
	key, err := ImportPublicKeyfromPEM([]byte(pemECPublicKeyP384))
	if err != nil {
		t.Fail()
	}

	if FingerprintSHA256(key) != "ihs3yKBsfPblPVQ/Lnwsw0mix8GjA3RJXntKbB6g+r8" {
		t.Fail()
	}
}

func TestVarECPrivateKey(t *testing.T) {
	if ECPrivateKey != "EC PRIVATE KEY" {
		t.Fail()
	}
}

func TestVarECPublicKey(t *testing.T) {
	if ECPublicKey != "EC PUBLIC KEY" {
		t.Fail()
	}
}

func TestVarSDPublicKey(t *testing.T) {
	if SDPublicKey != "PUBLIC KEY" {
		t.Fail()
	}
}

func TestEncode(t *testing.T) {
	t.SkipNow()
}

func TestDecode(t *testing.T) {
	t.SkipNow()
}
