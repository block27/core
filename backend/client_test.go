package backend

import (
	"testing"
)

func TestNewBackend(t *testing.T) {
	backend, err := NewBackend()
	if err != nil {
		t.Fail()
	}

	if backend.C == nil {
		t.Fail()
	}

	if backend.D == nil {
		t.Fail()
	}

	if backend.L == nil {
		t.Fail()
	}
}

func TestRequestHardwareKeys(t *testing.T) {
	t.SkipNow()
}

func TestRequestValidateKeys(t *testing.T) {
	t.SkipNow()
}

func TestRequestWelcome(t *testing.T) {
	t.SkipNow()
}
