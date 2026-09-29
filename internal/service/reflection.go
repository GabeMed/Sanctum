package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/google/uuid"
)

// ErrEmptyContent is returned by Create when the content is empty or only
// whitespace.
var ErrEmptyContent = errors.New("content must not be empty")

// ReflectionService encrypts reflections before they are stored and decrypts
// them after they are read. It does not know how either step is done.
type ReflectionService struct {
	encryptor  Encryptor
	repository Repository
	now        func() time.Time
}

// NewReflectionService wires the service with its two dependencies.
func NewReflectionService(encryptor Encryptor, repository Repository) *ReflectionService {
	return &ReflectionService{
		encryptor:  encryptor,
		repository: repository,
		now:        time.Now,
	}
}

// Create encrypts content and stores it. The day is derived from the current
// UTC time. The plaintext is echoed back as confirmation.
func (s *ReflectionService) Create(ctx context.Context, content string) (domain.ReflectionOutput, error) {
	if strings.TrimSpace(content) == "" {
		return domain.ReflectionOutput{}, ErrEmptyContent
	}

	// Postgres TIMESTAMPTZ has microsecond precision; truncate so the value
	// returned here equals the value read back later.
	now := s.now().UTC().Truncate(time.Microsecond)

	envelope, err := s.encryptor.Encrypt([]byte(content))
	if err != nil {
		return domain.ReflectionOutput{}, fmt.Errorf("encrypt reflection: %w", err)
	}

	reflection := &domain.Reflection{
		ID:        uuid.New(),
		Day:       DayOf(now),
		Envelope:  *envelope,
		CreatedAt: now,
	}
	if err := s.repository.Save(ctx, reflection); err != nil {
		return domain.ReflectionOutput{}, fmt.Errorf("save reflection: %w", err)
	}

	return domain.ReflectionOutput{
		ID:        reflection.ID,
		Day:       reflection.Day,
		Content:   content,
		CreatedAt: reflection.CreatedAt,
	}, nil
}

// ListByDay returns the decrypted reflections of one day, or of every day
// when day is nil, oldest first.
func (s *ReflectionService) ListByDay(ctx context.Context, day *time.Time) ([]domain.ReflectionOutput, error) {
	var (
		stored []domain.Reflection
		err    error
	)
	if day == nil {
		stored, err = s.repository.FindAll(ctx)
	} else {
		stored, err = s.repository.FindByDay(ctx, DayOf(*day))
	}
	if err != nil {
		return nil, fmt.Errorf("list reflections: %w", err)
	}

	outputs := make([]domain.ReflectionOutput, 0, len(stored))
	for i := range stored {
		output, err := s.open(&stored[i])
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, output)
	}
	return outputs, nil
}

// GetByID returns one decrypted reflection. It returns domain.ErrNotFound if
// the reflection does not exist.
func (s *ReflectionService) GetByID(ctx context.Context, id uuid.UUID) (domain.ReflectionOutput, error) {
	stored, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return domain.ReflectionOutput{}, fmt.Errorf("get reflection %s: %w", id, err)
	}
	return s.open(stored)
}

func (s *ReflectionService) open(r *domain.Reflection) (domain.ReflectionOutput, error) {
	plaintext, err := s.encryptor.Decrypt(&r.Envelope)
	if err != nil {
		return domain.ReflectionOutput{}, fmt.Errorf("decrypt reflection %s: %w", r.ID, err)
	}
	return domain.ReflectionOutput{
		ID:        r.ID,
		Day:       r.Day,
		Content:   string(plaintext),
		CreatedAt: r.CreatedAt,
	}, nil
}

// DayOf returns midnight UTC of the calendar day t falls on in UTC.
func DayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
