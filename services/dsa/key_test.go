package dsa

import (
	"testing"
)

func TestGToString(t *testing.T) {
	if ToString("Prime256v1", "private") != "ec.privateKey <==> Prime256v1" {
		t.Fail()
	}
}
