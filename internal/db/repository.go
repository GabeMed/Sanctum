// Package db implements service.Repository on PostgreSQL with raw SQL
// (database/sql and the pgx driver, no ORM).
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/GabeMed/Sanctum/internal/domain"
	"github.com/GabeMed/Sanctum/migrations"
	"github.com/google/uuid"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Open connects to Postgres and checks the connection.
func Open(ctx context.Context, databaseURL string) (*sql.DB, error) {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(30 * time.Minute)

	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return conn, nil
}

// Migrate applies every embedded *.up.sql file in name order. The files use
// IF NOT EXISTS, so running Migrate on an up-to-date database is a no-op.
func Migrate(ctx context.Context, conn *sql.DB) error {
	names, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		statements, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(statements)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
	}
	return nil
}

// PostgresRepository stores reflections in the reflections table.
// It only ever receives and returns encrypted content.
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository returns a repository backed by db.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

const selectColumns = `SELECT id, day, nonce, encrypted_dek, ciphertext, created_at FROM reflections`

// Save inserts a reflection. Reflections are append-only: saving an existing
// id fails.
func (r *PostgresRepository) Save(ctx context.Context, reflection *domain.Reflection) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO reflections (id, day, nonce, encrypted_dek, ciphertext, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		reflection.ID,
		reflection.Day.UTC().Format(time.DateOnly),
		reflection.Nonce,
		reflection.EncryptedDEK,
		reflection.Ciphertext,
		reflection.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert reflection: %w", err)
	}
	return nil
}

// FindByDay returns the reflections of one day, oldest first.
func (r *PostgresRepository) FindByDay(ctx context.Context, day time.Time) ([]domain.Reflection, error) {
	return r.query(ctx,
		selectColumns+` WHERE day = $1 ORDER BY created_at, id`,
		day.UTC().Format(time.DateOnly))
}

// FindAll returns every reflection, oldest first.
func (r *PostgresRepository) FindAll(ctx context.Context) ([]domain.Reflection, error) {
	return r.query(ctx, selectColumns+` ORDER BY created_at, id`)
}

// FindByID returns domain.ErrNotFound if no reflection has the given id.
func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Reflection, error) {
	row := r.db.QueryRowContext(ctx, selectColumns+` WHERE id = $1`, id)
	reflection, err := scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("select reflection: %w", err)
	}
	return reflection, nil
}

func (r *PostgresRepository) query(ctx context.Context, query string, args ...any) ([]domain.Reflection, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("select reflections: %w", err)
	}
	defer rows.Close()

	reflections := []domain.Reflection{}
	for rows.Next() {
		reflection, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan reflection: %w", err)
		}
		reflections = append(reflections, *reflection)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reflections: %w", err)
	}
	return reflections, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scan(s scanner) (*domain.Reflection, error) {
	var (
		reflection domain.Reflection
		day        time.Time
	)
	err := s.Scan(
		&reflection.ID,
		&day,
		&reflection.Nonce,
		&reflection.EncryptedDEK,
		&reflection.Ciphertext,
		&reflection.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	reflection.Day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	reflection.CreatedAt = reflection.CreatedAt.UTC()
	return &reflection, nil
}
