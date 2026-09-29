package service

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/GabeMed/Sanctum/internal/crypto"
	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/google/uuid"
)

// memoryRepository is an in-memory Repository used only by these tests.
type memoryRepository struct {
	rows    map[uuid.UUID]domain.Reflection
	saveErr error
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{rows: map[uuid.UUID]domain.Reflection{}}
}

func (m *memoryRepository) Save(_ context.Context, r *domain.Reflection) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.rows[r.ID] = *r
	return nil
}

func (m *memoryRepository) FindByDay(ctx context.Context, day time.Time) ([]domain.Reflection, error) {
	all, _ := m.FindAll(ctx)
	var out []domain.Reflection
	for _, r := range all {
		if r.Day.Equal(day) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memoryRepository) FindAll(context.Context) ([]domain.Reflection, error) {
	out := make([]domain.Reflection, 0, len(m.rows))
	for _, r := range m.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *memoryRepository) FindByID(_ context.Context, id uuid.UUID) (*domain.Reflection, error) {
	r, ok := m.rows[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &r, nil
}

func newTestService(t *testing.T) (*ReflectionService, *memoryRepository, *time.Time) {
	t.Helper()
	engine, err := crypto.NewEngine(bytes.Repeat([]byte{0x42}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	repo := newMemoryRepository()
	svc := NewReflectionService(engine, repo)
	clock := time.Date(2026, 3, 4, 8, 30, 0, 123456789, time.UTC)
	svc.now = func() time.Time { return clock }
	return svc, repo, &clock
}

func TestCreate_StoresOnlyCiphertext(t *testing.T) {
	svc, repo, _ := newTestService(t)
	content := "Today I understood that patience is not passive"

	out, err := svc.Create(context.Background(), content)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if out.Content != content {
		t.Errorf("Content = %q, want %q", out.Content, content)
	}

	stored, ok := repo.rows[out.ID]
	if !ok {
		t.Fatal("reflection was not saved")
	}
	if bytes.Contains(stored.Ciphertext, []byte(content)) {
		t.Fatal("CRITICAL: plaintext found in stored ciphertext")
	}
	if len(stored.Nonce) != crypto.NonceSize || len(stored.EncryptedDEK) == 0 {
		t.Fatalf("stored envelope incomplete: %+v", stored.Envelope)
	}
}

func TestCreate_DerivesDayAndTimestamp(t *testing.T) {
	svc, _, clock := newTestService(t)
	// 23:59 at UTC-3 is already the next day in UTC.
	*clock = time.Date(2026, 3, 4, 23, 59, 0, 0, time.FixedZone("BRT", -3*3600))

	out, err := svc.Create(context.Background(), "late night")
	if err != nil {
		t.Fatal(err)
	}
	wantDay := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	if !out.Day.Equal(wantDay) || out.Day.Location() != time.UTC {
		t.Errorf("Day = %v, want %v", out.Day, wantDay)
	}
	if out.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt not in UTC: %v", out.CreatedAt)
	}
	if out.CreatedAt.Nanosecond()%1000 != 0 {
		t.Errorf("CreatedAt not truncated to microseconds: %v", out.CreatedAt)
	}
}

func TestCreate_RejectsEmptyContent(t *testing.T) {
	svc, repo, _ := newTestService(t)
	for _, content := range []string{"", "   ", "\n\t"} {
		if _, err := svc.Create(context.Background(), content); !errors.Is(err, ErrEmptyContent) {
			t.Errorf("Create(%q): expected ErrEmptyContent, got %v", content, err)
		}
	}
	if len(repo.rows) != 0 {
		t.Fatal("empty content was saved")
	}
}

func TestCreate_PropagatesSaveError(t *testing.T) {
	svc, repo, _ := newTestService(t)
	repo.saveErr = errors.New("disk full")
	if _, err := svc.Create(context.Background(), "x"); !errors.Is(err, repo.saveErr) {
		t.Fatalf("expected save error, got %v", err)
	}
}

func TestGetByID_RoundTrip(t *testing.T) {
	svc, _, _ := newTestService(t)
	created, err := svc.Create(context.Background(), "In principio erat Verbum")
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != created.ID || got.Content != created.Content ||
		!got.Day.Equal(created.Day) || !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("GetByID = %+v, want %+v", got, created)
	}
}

func TestGetByID_NotFound(t *testing.T) {
	svc, _, _ := newTestService(t)
	if _, err := svc.GetByID(context.Background(), uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetByID_TamperedRowFails(t *testing.T) {
	svc, repo, _ := newTestService(t)
	created, err := svc.Create(context.Background(), "secret")
	if err != nil {
		t.Fatal(err)
	}
	row := repo.rows[created.ID]
	row.Ciphertext[0] ^= 0x01
	repo.rows[created.ID] = row

	if _, err := svc.GetByID(context.Background(), created.ID); err == nil {
		t.Fatal("CRITICAL: tampered row decrypted")
	}
}

func TestListByDay(t *testing.T) {
	svc, _, clock := newTestService(t)
	ctx := context.Background()

	day1 := time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC)
	day2 := day1.AddDate(0, 0, 1)
	for i, at := range []time.Time{day1, day1.Add(time.Hour), day2} {
		*clock = at
		if _, err := svc.Create(ctx, []string{"first", "second", "third"}[i]); err != nil {
			t.Fatal(err)
		}
	}

	onDay1, err := svc.ListByDay(ctx, &day1)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDay1) != 2 || onDay1[0].Content != "first" || onDay1[1].Content != "second" {
		t.Fatalf("ListByDay(day1) = %+v", onDay1)
	}

	all, err := svc.ListByDay(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 {
		t.Fatalf("ListByDay(nil) returned %d reflections, want 3", len(all))
	}

	empty := day2.AddDate(0, 0, 1)
	none, err := svc.ListByDay(ctx, &empty)
	if err != nil {
		t.Fatal(err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("ListByDay(empty day) = %#v, want empty non-nil slice", none)
	}
}

func TestDayOf(t *testing.T) {
	in := time.Date(2026, 12, 31, 22, 0, 0, 0, time.FixedZone("UTC-3", -3*3600))
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := DayOf(in); !got.Equal(want) || got.Location() != time.UTC {
		t.Fatalf("DayOf(%v) = %v, want %v", in, got, want)
	}
}
