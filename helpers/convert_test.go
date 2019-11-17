package helpers

import (
	"testing"
)

var (
	prime256v1PrivateKey = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454f506a7569626a56746d63532f4b46494a7164324f344a753756696d0a434f624d356378704563597435413063316d423469646e52664538476e7234344c374546455356397965514f4f362f67664875504b39517538673d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"
	secp256k1PrivateKey  = "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d465977454159484b6f5a497a6a3043415159464b34454541416f4451674145794b654f4e2b56635164792b503171666f4c747a6866753234744733524951700a41694b6151525939456173766b4d6369706e364b506f51722f756d423145396e5a7663336b6c723049706b6e72526b51796c494976513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a"
)

func TestBytesToString(t *testing.T) {
	if BytesToString([]byte("alex")) != "alex" {
		t.Fail()
	}

	if BytesToString([]byte("02g8j30g8204gh10e8vbjw0djf2")) != "02g8j30g8204gh10e8vbjw0djf2" {
		t.Fail()
	}

	if BytesToString([]byte(")*&*^&R&^(*_(*))")) != ")*&*^&R&^(*_(*))" {
		t.Fail()
	}
}

func TestBytesToHex(t *testing.T) {
	if BytesToHex([]byte("alex")) != "616c6578" {
		t.Fail()
	}

	// Prime public key
	prime, err := NewFile("../data/keys/ecdsa/prime256v1-pubkey.pem")
	if err != nil {
		t.Fail()
	}

	if BytesToHex(prime.GetBody()) != prime256v1PrivateKey {
		t.Fail()
	}

	// Secp public key
	secp, err := NewFile("../data/keys/ecdsa/secp256k1-pubkey.pem")
	if err != nil {
		t.Fail()
	}

	if BytesToHex(secp.GetBody()) != secp256k1PrivateKey {
		t.Fail()
	}
}
