package utils

import "unicode"

// ASCIIBytesToPrintString converts the buffer b to the closest ASCII string
// equivalent, substituting '*' for unprintable characters.
func ASCIIBytesToPrintString(b []byte) string {
	r := make([]byte, 0, len(b))

	// This should *never* be used in production, since it attempts to give a
	// printable representation of a byte sequence for debug logging, and it's
	// slow.
	for _, v := range b {
		if v <= unicode.MaxASCII && unicode.IsPrint(rune(v)) {
			r = append(r, v)
		} else {
			r = append(r, '*') // At least I didn't pick `:poop:`.
		}
	}
	return string(r)
}
