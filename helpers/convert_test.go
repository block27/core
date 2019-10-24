package helpers

import (
	"testing"
)

func TestBytesToString(t *testing.T) {
	if BytesToString([]byte("alex")) != "alex" {
		t.Fail()
	}
}
