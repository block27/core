package dsa

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"sync"
	"time"

	guuid "github.com/google/uuid"
)

// KeyAttributes is the baseline key/values needed to identify a key for system
// storage.
type KeyAttributes struct {
	sink sync.Mutex // mutex to allow clean concurrent access
	GID  guuid.UUID // guuid for crypto identification

	// Base name passed from CLI, *not indexed
	Name string

	// Slug auto generated from Haiku *not indexed
	Slug string

	// Hold the base key status, {archive, active}
	Status string

	// Basically the elliptic curve size of the key
	KeyType string

	FingerprintMD5 string // Real fingerprint in  MD5  (legacy)  of the key
	FingerprintSHA string // Real fingerprint in  SHA256  of the key

	CreatedAt time.Time
}

// KAToGOB64 takes a pointer to an existing key and return it's entire body
// object base64 encoded for storage.
func KAToGOB64(ka *KeyAttributes) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)

	if err := e.Encode(ka); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// KAFromGOB64 takes a base64 encoded string and convert that to an object. We
// need a way to handle updates here.
func KAFromGOB64(str string) (*KeyAttributes, error) {
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return (*KeyAttributes)(nil), err
	}

	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)

	var ka *KeyAttributes

	if err = d.Decode(&ka); err != nil {
		return (*KeyAttributes)(nil), err
	}

	return ka, nil
}

// ToString prints a helpful description of the key and it's type
func ToString(curve string, pk string) string {
	return fmt.Sprintf("ec.%sKey <==> %s", pk, curve)
}
