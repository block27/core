package dsa

import (
	guuid "github.com/google/uuid"
)

const (
	// StatusActive is for active and currently used keys
	StatusActive   = "active"

	// StatusArchived is for keys that are "soft" deleted and no longer in use
	StatusArchived = "archive"
)

// GenerateUUID generate and return a valid google.GUUID
func GenerateUUID() guuid.UUID {
	return guuid.New()
}

// WriteToFS ...
// func WriteToFS(i interface{}) {
// 	switch v := i.(type) {
// 	case ecdsa.KeyAPI:
// 		fmt.Println("ECDSA: ", v)
// 	case eddsa.KeyAPI:
// 		fmt.Println("EDDSA: ", v)
// 	}
// }
