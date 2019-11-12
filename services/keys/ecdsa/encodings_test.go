package keys

import "testing"

func TestVar_ecPrivateKey(t *testing.T) {
	if ecPrivateKey != "EC PRIVATE KEY" {
		t.Fail()
	}
}

func TestVar_ecPublicKey(t *testing.T) {
	if ecPublicKey != "EC PUBLIC KEY" {
		t.Fail()
	}
}

func TestVar_sdPublicKey(t *testing.T) {
	if sdPublicKey != "PUBLIC KEY" {
		t.Fail()
	}
}
