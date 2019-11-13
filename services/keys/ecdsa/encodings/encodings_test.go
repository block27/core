package encodings

import "testing"

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

func TestFingerprintMD5(t *testing.T) {
	t.SkipNow()
}

func TestFingerprintSHA256(t *testing.T) {
	t.SkipNow()
}

func TestEncode(t *testing.T) {
	t.SkipNow()
}

func TestDecode(t *testing.T) {
	t.SkipNow()
}
