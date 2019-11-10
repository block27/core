package utils

import "testing"

func TestEnsureAddrIPPort(t *testing.T) {
	if EnsureAddrIPPort("192.168.100.104") == nil {
		t.Fail()
	}

	if EnsureAddrIPPort("alex") == nil {
		t.Fail()
	}

	if EnsureAddrIPPort("192.168.100.104:1000") != nil {
		t.Fail()
	}
}
