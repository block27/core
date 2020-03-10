package dsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGToString(t *testing.T) {
	if ToString("Prime256v1", "private") != "ec.privateKey <==> Prime256v1" {
		t.Fail()
	}
}

func TestKeyID(t *testing.T) {
	assert.Equal(t, "pending", NewKA().Status)
}
