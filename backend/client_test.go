package backend

import (
	"testing"
)

var backend *Backend

func init() {
	var err error

	backend, err = NewBackend()
	if err != nil {
		panic(err)
	}
}

func TestNewBackend(t *testing.T) {
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

// func TestLocateDevice(t *testing.T) {
// 	backend, err := NewBackend()
// 	if err != nil {
// 		t.Fail()
// 	}
//
// 	d, e := backend.LocateDevice()
// 	if e != nil {
// 		t.Fail()
// 	}
//
// 	if !strings.Contains("/dev/tty.usbmodem", d) {
// 		t.Fail()
// 	}
// }

func TestHardwareAuthenticate(t *testing.T) {
	t.SkipNow()
}

func TestRequestHardwareKeys(t *testing.T) {
	t.SkipNow()
}

func TestWelcome(t *testing.T) {
	t.SkipNow()
}
