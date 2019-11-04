package crypto

import (
	"testing"
)

var e EntropyAPI

func init() {
	e = NewEntropy()
}

func TestPing(t  *testing.T) {
	result, _ := e.Ping()

	if result != "pong" {
		t.Fail()
	}
}

func TestPoolsize(t  *testing.T) {
	result, _ := e.PoolSize()

	if result != 0 {
		t.Fail()
	}
}
