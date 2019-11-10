package utils

import (
	"testing"
)

func TestASCIIBytesToPrintString(t *testing.T) {
	res1 := ASCIIBytesToPrintString([]byte("hello"))

	if res1 != "hello" {
		t.Fail()
	}

	res2 := ASCIIBytesToPrintString([]byte("@#%$"))

	if res2 != "@#%$" {
		t.Fail()
	}

	res3 := ASCIIBytesToPrintString([]byte("😎"))

	if res3 != "****" {
		t.Fail()
	}
}
