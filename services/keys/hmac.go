package keys


import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"io"
)

// NewHMACKey generates a random 256-bit secret key for HMAC use.
// Because key generation is critical, it panics if the source of randomness fails.
func NewHMACKey() *[32]byte {
	key := &[32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

// GenerateHMAC produces a symmetric signature using a shared secret key.
func GenerateHMAC(data []byte, key *[32]byte) []byte {
	h := hmac.New(sha512.New512_256, key[:])
	h.Write(data)
	return h.Sum(nil)

}

// CheckHMAC securely checks the supplied MAC against a message using the shared secret key.
func CheckHMAC(data, suppliedMAC []byte, key *[32]byte) bool {
	expectedMAC := GenerateHMAC(data, key)
	return hmac.Equal(expectedMAC, suppliedMAC)
}
