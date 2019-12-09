package dsa

import (
	guuid "github.com/google/uuid"
)

const (
	// StatusActive ...
	StatusActive   = "active"

	// StatusArchived ...
	StatusArchived = "archive"
)

// GenerateUUID - generate and return a valid GUUID
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
