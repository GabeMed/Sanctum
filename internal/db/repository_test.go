package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/GabeMed/Sanctum/internal/crypto"
	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/google/uuid"
)

// These are integration tests against a real Postgres. They run only when
// SANCTUM_TEST_DATABASE_URL is set, e.g. by `make test-integration` or CI.
// They drop and recreate the reflections table: never point them at a
// database you care about.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("SANCTUM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SANCTUM_TEST_DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx := context.Background()
	conn, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := conn.ExecContext(ctx, `DROP TABLE IF EXISTS reflections`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return conn
}

func sealed(t *testing.T, engine *crypto.Engine, content string, createdAt time.Time) *domain.Reflection {
	t.Helper()
	envelope, err := engine.Encrypt([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	createdAt = createdAt.UTC().Truncate(time.Microsecond)
	y, m, d := createdAt.Date()
	return &domain.Reflection{
		ID:        uuid.New(),
		Day:       time.Date(y, m, d, 0, 0, 0, 0, time.UTC),
		Envelope:  *envelope,
		CreatedAt: createdAt,
	}
}

func testEngine(t *testing.T) *crypto.Engine {
	t.Helper()
	engine, err := crypto.NewEngine(bytes.Repeat([]byte{7}, crypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestMigrate_Idempotent(t *testing.T) {
	conn := openTestDB(t)
	if err := Migrate(context.Background(), conn); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestPostgres_SaveAndFindByID(t *testing.T) {
	conn := openTestDB(t)
	repo := NewPostgresRepository(conn)
	engine := testEngine(t)
	ctx := context.Background()

	want := sealed(t, engine, "Forgive me, Father, for I have sinned", time.Date(2026, 3, 4, 8, 30, 0, 123456000, time.UTC))
	if err := repo.Save(ctx, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.FindByID(ctx, want.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != want.ID || !got.Day.Equal(want.Day) || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("metadata mismatch: got %+v, want %+v", got, want)
	}
	if !bytes.Equal(got.Nonce, want.Nonce) ||
		!bytes.Equal(got.EncryptedDEK, want.EncryptedDEK) ||
		!bytes.Equal(got.Ciphertext, want.Ciphertext) {
		t.Fatal("envelope bytes changed in storage")
	}

	plaintext, err := engine.Decrypt(&got.Envelope)
	if err != nil {
		t.Fatalf("Decrypt after round trip through Postgres: %v", err)
	}
	if string(plaintext) != "Forgive me, Father, for I have sinned" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestPostgres_FindByIDNotFound(t *testing.T) {
	repo := NewPostgresRepository(openTestDB(t))
	if _, err := repo.FindByID(context.Background(), uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPostgres_FindByDayAndAll(t *testing.T) {
	repo := NewPostgresRepository(openTestDB(t))
	engine := testEngine(t)
	ctx := context.Background()

	base := time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC)
	// Saved out of order to check ORDER BY created_at.
	later := sealed(t, engine, "later", base.Add(2*time.Hour))
	earlier := sealed(t, engine, "earlier", base)
	nextDay := sealed(t, engine, "next day", base.AddDate(0, 0, 1))
	for _, r := range []*domain.Reflection{later, earlier, nextDay} {
		if err := repo.Save(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	onDay, err := repo.FindByDay(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(onDay) != 2 || onDay[0].ID != earlier.ID || onDay[1].ID != later.ID {
		t.Fatalf("FindByDay returned %d rows in wrong order or content", len(onDay))
	}

	all, err := repo.FindAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[2].ID != nextDay.ID {
		t.Fatalf("FindAll returned %d rows or wrong order", len(all))
	}

	none, err := repo.FindByDay(ctx, base.AddDate(0, 0, 10))
	if err != nil {
		t.Fatal(err)
	}
	if none == nil || len(none) != 0 {
		t.Fatalf("FindByDay(empty day) = %#v, want empty non-nil slice", none)
	}
}

func TestPostgres_AppendOnly(t *testing.T) {
	repo := NewPostgresRepository(openTestDB(t))
	r := sealed(t, testEngine(t), "once", time.Now())
	if err := repo.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(context.Background(), r); err == nil {
		t.Fatal("saving the same id twice succeeded")
	}
}

func TestPostgres_RejectsMalformedEnvelope(t *testing.T) {
	repo := NewPostgresRepository(openTestDB(t))
	r := sealed(t, testEngine(t), "x", time.Now())
	r.Nonce = r.Nonce[:8]
	if err := repo.Save(context.Background(), r); err == nil {
		t.Fatal("row with an 8-byte nonce was accepted")
	}
}

// TestPostgres_StoresNoPlaintext reads the raw row and checks the content is
// not stored in any column.
func TestPostgres_StoresNoPlaintext(t *testing.T) {
	conn := openTestDB(t)
	repo := NewPostgresRepository(conn)
	content := "a sentence that must never reach the disk in plaintext"
	r := sealed(t, testEngine(t), content, time.Now())
	if err := repo.Save(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	var rowText string
	err := conn.QueryRowContext(context.Background(),
		`SELECT row_to_json(reflections)::text FROM reflections WHERE id = $1`, r.ID).Scan(&rowText)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	err = conn.QueryRowContext(context.Background(),
		`SELECT nonce || encrypted_dek || ciphertext FROM reflections WHERE id = $1`, r.ID).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(rowText), []byte(content)) || bytes.Contains(raw, []byte(content)) {
		t.Fatal("CRITICAL: plaintext found in stored row")
	}
}
