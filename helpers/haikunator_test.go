package helpers

import (
	"testing"
)

func TestProbability(t *testing.T) {
	if NewHaikunator().Probability() < 100000000 {
		t.Fail()
	}
}
