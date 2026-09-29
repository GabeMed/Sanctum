package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

var validEnv = map[string]string{
	"DATABASE_URL":      "postgres://localhost/sanctum",
	"SANCTUM_API_TOKEN": strings.Repeat("t", MinTokenLength),
	"SANCTUM_KEK":       base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
}

func with(key, value string) map[string]string {
	out := map[string]string{}
	for k, v := range validEnv {
		out[k] = v
	}
	out[key] = value
	return out
}

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load(env(validEnv))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q, want default :8080", cfg.Addr)
	}
	if !bytes.Equal(cfg.KEK, bytes.Repeat([]byte{1}, 32)) {
		t.Errorf("KEK not decoded")
	}

	cfg, err = Load(env(with("SANCTUM_ADDR", "127.0.0.1:9000")))
	if err != nil || cfg.Addr != "127.0.0.1:9000" {
		t.Errorf("Addr override: %q, %v", cfg.Addr, err)
	}
}

func TestLoad_Invalid(t *testing.T) {
	cases := map[string]map[string]string{
		"no database":   with("DATABASE_URL", ""),
		"no token":      with("SANCTUM_API_TOKEN", ""),
		"short token":   with("SANCTUM_API_TOKEN", "short"),
		"no kek":        with("SANCTUM_KEK", ""),
		"kek not b64":   with("SANCTUM_KEK", "not base64!"),
		"kek 16 bytes":  with("SANCTUM_KEK", base64.StdEncoding.EncodeToString(make([]byte, 16))),
		"kek raw bytes": with("SANCTUM_KEK", strings.Repeat("k", 32)),
	}
	for name, values := range cases {
		if _, err := Load(env(values)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
