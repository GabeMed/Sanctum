// Package service orchestrates encryption and storage of reflections.
//
// The interfaces below are defined here, where they are consumed, and are
// implemented by internal/crypto (Encryptor) and internal/db (Repository).
package service

import (
	"context"
	"time"

	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/google/uuid"
)

// Encryptor defines what the Service needs from the crypto layer.
type Encryptor interface {
	Encrypt(plaintext []byte) (*domain.Envelope, error)
	Decrypt(envelope *domain.Envelope) ([]byte, error)
}

// Repository defines what the Service needs from the storage layer.
// It only ever sees encrypted content.
type Repository interface {
	Save(ctx context.Context, r *domain.Reflection) error
	FindByDay(ctx context.Context, day time.Time) ([]domain.Reflection, error)
	FindAll(ctx context.Context) ([]domain.Reflection, error)
	// FindByID returns domain.ErrNotFound if no reflection has the given id.
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Reflection, error)
}
