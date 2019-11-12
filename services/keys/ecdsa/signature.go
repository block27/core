package keys

import (
	"encoding/asn1"
	"encoding/hex"
	"math/big"

	"github.com/amanelis/bespin/helpers"
)

type ecdsaSigner struct {
	SHA [32]byte
	MD5 [16]byte

	// File path of the hashed object or file using for signature
	File string

	// Sig, when converting to asn1, only the R,S attributes can be in the struct
	Sig *ecdsaSignature
}

// ecdsaSignature - just used to hold a signature and pass around a bit nicer
//
type ecdsaSignature struct {
	// Standard resulting signature values
	R, S *big.Int
}

func (e *ecdsaSigner) WriteToDER(file string) ([]byte, error) {
	data, err := asn1.Marshal(*e.Sig)
	if err != nil {
		return nil, err
	}

	if _, err := helpers.WriteBinary(file, data); err != nil {
		return nil, err
	}

	return data, nil
}

// PointsToDER ...
// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
//
func (e *ecdsaSigner) PointsToDER() []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs
	prefixPoint := func(b []byte) []byte {
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			paddedBytes := make([]byte, len(b)+1)
			copy(paddedBytes[1:], b)
			b = paddedBytes
		}
		return b
	}

	rb := prefixPoint(e.Sig.R.Bytes())
	sb := prefixPoint(e.Sig.S.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	encoded := make([]byte, hex.EncodedLen(len(der)))
	hex.Encode(encoded, der)

	return encoded
}

// PointsFromDER ...
// Get the X and Y points from a DER encoded signature
// Sometimes demarshalling using Golang's DEC to struct unmarshalling fails; this extracts R and S from the bytes
// manually to prevent crashing.
// This should NOT be a hex encoded byte array
func (e *ecdsaSignature) PointsFromDER(der []byte) (R, S *big.Int) {
	R, S = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	if _, err := asn1.Unmarshal(der, &data); err != nil {
		panic(err.Error())
	}

	// The format of our DER string is 0x02 + rlen + r + 0x02 + slen + s
	rLen := data.Bytes[1] // The entire length of R + offset of 2 for 0x02 and rlen
	r := data.Bytes[2 : rLen+2]
	// Ignore the next 0x02 and slen bytes and just take the start of S to the end of the byte array
	s := data.Bytes[rLen+4:]

	R.SetBytes(r)
	S.SetBytes(s)

	return
}

// canonicalizeInt returns the bytes for the passed big integer adjusted as
// necessary to ensure that a big-endian encoded integer can't possibly be
// misinterpreted as a negative number.  This can happen when the most
// significant bit is set, so it is padded by a leading zero byte in this case.
// Also, the returned bytes will have at least a single byte when the passed
// value is 0.  This is required for DER encoding.
func canonicalizeInt(val *big.Int) []byte {
	b := val.Bytes()
	if len(b) == 0 {
		b = []byte{0x00}
	}

	if b[0]&0x80 != 0 {
		paddedBytes := make([]byte, len(b)+1)
		copy(paddedBytes[1:], b)
		b = paddedBytes
	}

	return b
}
