package crypto

import (
	"testing"
)

func TestRead(t  *testing.T) {
	result, err := Reader.Read(make([]byte, 1))

	if err != nil || result <= 0 {
		t.Fail()
	}
}
