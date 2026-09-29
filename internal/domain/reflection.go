// Package domain holds the core types of Sanctum. It has no dependencies on
// HTTP, SQL or cryptography.
package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a reflection does not exist.
var ErrNotFound = errors.New("reflection not found")

// Envelope is the encrypted form of a reflection's content.
//
// Ciphertext is the content encrypted with a per-reflection Data Encryption
// Key (DEK). EncryptedDEK is that DEK wrapped by the Key Encryption Key (KEK).
// Nonce is the AES-GCM nonce; it is not secret.
type Envelope struct {
	Nonce        []byte
	EncryptedDEK []byte
	Ciphertext   []byte
}

// Reflection is a reflection as it is stored: metadata in plaintext, content
// only as an Envelope.
type Reflection struct {
	ID  uuid.UUID
	Day time.Time // UTC midnight of the day the reflection was written
	Envelope
	CreatedAt time.Time
}

// ReflectionOutput is a decrypted reflection, as returned to the client.
type ReflectionOutput struct {
	ID        uuid.UUID
	Day       time.Time
	Content   string
	CreatedAt time.Time
}
