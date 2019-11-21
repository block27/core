package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// https://groups.google.com/d/msg/sci.crypt/OolWgsgQD-8/jHciyWkaL0gJ
var hmacTests = []struct {
	key    string
	data   string
	digest string
}{
	{
		key:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		data:   "4869205468657265", // "Hi There"
		digest: "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab",
	},
	{
		key:    "4a656665",                                                 // "Jefe"
		data:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
		digest: "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456",
	},
}

func TestHMAC(t *testing.T) {
	for idx, tt := range hmacTests {
		keySlice, _ := hex.DecodeString(tt.key)
		dataBytes, _ := hex.DecodeString(tt.data)
		expectedDigest, _ := hex.DecodeString(tt.digest)

		keyBytes := &[32]byte{}
		copy(keyBytes[:], keySlice)

		macDigest := GenerateHMAC(dataBytes, keyBytes)
		if !bytes.Equal(macDigest, expectedDigest) {
			t.Errorf("test %d generated unexpected mac", idx)
		}
	}
}
