package helpers

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"unsafe"
)

// BytesToString ...
func BytesToString(b []byte) string {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := reflect.StringHeader{
		Data: bh.Data,
		Len:  bh.Len,
	}

	return *(*string)(unsafe.Pointer(&sh))
}

// BytesToHex ...
func BytesToHex(b []byte) string {
	dst := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(dst, b)

	return fmt.Sprintf("%s", dst)
}
