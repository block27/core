package dsa

import (
	"regexp"
	"testing"
)

var Curves = []string{
	"prime256v1",
	// "secp224r1",
	"secp384r1",
	"secp521r1",
}

func TestGetConstants(t *testing.T) {
	if Public != "public" {
		t.Fail()
	}

	if Private != "private" {
		t.Fail()
	}

	if StatusActive != "active" {
		t.Fail()
	}

	if StatusArchived != "archive" {
		t.Fail()
	}
}

func TestGetCurve(t *testing.T) {
	for _, curve := range Curves {
		if _, c, _, e := GetCurve(curve); e != nil || c != curve {
			t.Fatalf("failed to getCurve on %s", curve)
		}
	}

	// invalid
	if _, _, _, e := GetCurve("junk"); e == nil {
		t.Fail()
	}
}

func TestGenerateUUID(t *testing.T) {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	if !r.MatchString(GenerateUUID().String()) {
		t.Fail()
	}
}
