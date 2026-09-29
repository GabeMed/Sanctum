-- Sanctum V1 schema. See docs/rfc.md, section 4.
CREATE TABLE IF NOT EXISTS reflections (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    day           DATE        NOT NULL,
    nonce         BYTEA       NOT NULL CHECK (octet_length(nonce) = 12),
    encrypted_dek BYTEA       NOT NULL CHECK (octet_length(encrypted_dek) = 48),
    ciphertext    BYTEA       NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Serves both "WHERE day = $1" and ordering within a day.
CREATE INDEX IF NOT EXISTS idx_reflections_day_created ON reflections (day, created_at);
