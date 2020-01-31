package crypto

import (
	"github.com/awnumar/memguard"

	"testing"
)

var e EntropyAPI

func init() {
	e = NewEntropy()
}

func TestPing(t *testing.T) {
	result, _ := e.Ping()

	if result != "pong" {
		t.Fail()
	}
}

func TestPoolsize(t *testing.T) {
	result, _ := e.PoolSize()

	if result != 0 {
		t.Fail()
	}
}

func TestNewAESCredentialsEnclave(t *testing.T) {
	ky := "U9nBGN9RxgzVMME7qpJ6YrlOwB7YS0sz"
	iv := "ZJwBycugYrZ6mnmz"

	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	defer memguard.Purge()

	res, err := NewAESCredentialsEnclave(
		memguard.NewEnclave([]byte(ky)),
		memguard.NewEnclave([]byte(iv)),
	)
	if err != nil {
		t.Fail()
	}

	if res.key == nil || res.iv == nil{
		t.Fail()
	}

	eKy, err := res.key.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer eKy.Destroy()

	eKy.Melt()
	if string(eKy.Bytes()) != ky {
		t.Errorf("%s : %s\n", string(eKy.Bytes()), ky)
	}

	eIv, err := res.iv.Open()
	if err != nil {
		memguard.SafePanic(err)
	}
	defer eIv.Destroy()

	eIv.Melt()
	if string(eIv.Bytes()) != iv {
		t.Errorf("%s : %s\n", string(eIv.Bytes()), iv)
	}

	// Destroy the session  data
	memguard.Purge()
}
