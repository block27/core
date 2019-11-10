package utils

// CtIsZero returns true iff the buffer b is all 0x00, doing the check in
// constant time.
func CtIsZero(b []byte) bool {
	var sum byte
	for _, v := range b {
		sum |= v
	}
	return sum == 0
}
