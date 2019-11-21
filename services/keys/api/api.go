package api

import (
	guuid "github.com/google/uuid"
)

const (
	StatusActive   = "active"
	StatusArchived = "archive"
)

// GenerateUUID - generate and return a valid GUUID
func GenerateUUID() guuid.UUID {
	return guuid.New()
}
