package dsa

import (
	"crypto/elliptic"
	"fmt"

	"github.com/block27/core/helpers"
	guuid "github.com/google/uuid"
	"github.com/spacemonkeygo/openssl"
)

const (
	// StatusActive is for active and currently used keys
	StatusActive = "active"

	// StatusArchived is for keys that are "soft" deleted and no longer in use
	StatusArchived = "archive"

	// Public string constant for type setting
	Public = "public"

	// Private string constant for type setting
	Private = "private"
)

// EC ...
type EC struct{}

// GetCurve checks the string param matched and should return a valid ec curve
func GetCurve(curve string) (elliptic.Curve, string, openssl.EllipticCurve, error) {
	switch curve {
	case "prime256v1": // prime256v1: X9.62/SECG curve over a 256 bit prime field
		return elliptic.P256(), "prime256v1", openssl.Prime256v1, nil
	case "secp384r1": // secp384r1: NIST/SECG curve over a 384 bit prime field
		return elliptic.P384(), "secp384r1", openssl.Secp384r1, nil
	case "secp521r1": // secp521r1: NIST/SECG curve over a 521 bit prime field
		return elliptic.P521(), "secp521r1", openssl.Secp521r1, nil
	default:
		return nil, "", 0, fmt.Errorf("%s", helpers.RFgB("incorrect curve size passed"))
	}
}

// GenerateUUID generate and return a valid google.GUUID
func GenerateUUID() guuid.UUID {
	return guuid.New()
}
