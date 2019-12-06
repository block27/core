package test

import (
	"testing"
)

// ByteEq ...
func ByteEq(t *testing.T, a, b []byte) bool {
	t.Helper()

	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
