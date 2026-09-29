// Package config reads Sanctum's settings from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// MinTokenLength is the shortest API token accepted.
const MinTokenLength = 32

// Config is everything the server needs to start.
type Config struct {
	Addr        string // SANCTUM_ADDR, default ":8080"
	DatabaseURL string // DATABASE_URL
	APIToken    string // SANCTUM_API_TOKEN
	KEK         []byte // SANCTUM_KEK, base64 of 32 random bytes
}

// Load builds a Config from getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Addr:        getenv("SANCTUM_ADDR"),
		DatabaseURL: getenv("DATABASE_URL"),
		APIToken:    getenv("SANCTUM_API_TOKEN"),
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	var errs []error
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if len(cfg.APIToken) < MinTokenLength {
		errs = append(errs, fmt.Errorf("SANCTUM_API_TOKEN must be at least %d characters (try: openssl rand -hex 32)", MinTokenLength))
	}

	rawKEK := strings.TrimSpace(getenv("SANCTUM_KEK"))
	kek, err := base64.StdEncoding.DecodeString(rawKEK)
	switch {
	case rawKEK == "":
		errs = append(errs, errors.New("SANCTUM_KEK is required (try: openssl rand -base64 32)"))
	case err != nil:
		errs = append(errs, errors.New("SANCTUM_KEK must be standard base64"))
	case len(kek) != 32:
		errs = append(errs, fmt.Errorf("SANCTUM_KEK must decode to 32 bytes, got %d", len(kek)))
	default:
		cfg.KEK = kek
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
