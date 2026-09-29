# Sanctum

Basic project focused in learning how to build scalable and reliable systems.

Sanctum is a small, single-tenant HTTP API for a daily journal. It stores
each entry ("reflection") in PostgreSQL using **envelope encryption**: every
reflection is encrypted with its own random key, and that key is itself
encrypted with a master key that never touches the database. The API is
append-only: reflections can be created and read, never edited or deleted.

It is written in Go with the standard library for HTTP and cryptography,
`database/sql` + [pgx](https://github.com/jackc/pgx) for Postgres, and no
framework. The design is written up in [`docs/rfc.md`](docs/rfc.md),
[`docs/architecture.md`](docs/architecture.md) and
[`docs/DOMAIN.md`](docs/DOMAIN.md).

## Currently implemented
- [x] Software Documentation
- [x] Envelop Encryption Logic
- [x] Main router
- [x] Database repository
- [x] Main interfaces

## Architecture

```mermaid
flowchart TD
    client["Client (curl, CLI)"]
    subgraph server["Sanctum server (cmd/server)"]
        mw["Middleware<br/>LogRequests, RequireToken"]
        handler["internal/handler<br/>JSON, validation, status codes"]
        service["internal/service<br/>ReflectionService"]
        enc["internal/crypto<br/>Engine: AES-256-GCM envelope encryption"]
        repo["internal/db<br/>PostgresRepository: raw SQL"]
    end
    db[("PostgreSQL<br/>reflections table")]
    env["Environment<br/>SANCTUM_KEK, SANCTUM_API_TOKEN"]

    client -- "plaintext JSON<br/>Authorization: Bearer" --> mw --> handler
    handler -- "Create / ListByDay / GetByID" --> service
    service -- "Encryptor interface" --> enc
    service -- "Repository interface" --> repo
    repo -- "nonce, encrypted_dek, ciphertext,<br/>day, created_at" --> db
    env -. "KEK at startup" .-> enc
```

Dependencies point inward. The handler knows HTTP but not AES or SQL. The
service knows the `Encryptor` and `Repository` interfaces
(`internal/service/interfaces.go`) but not how they are implemented. The
repository only ever sees ciphertext. `cmd/server/main.go` builds every
piece with plain constructors.

### Envelope encryption

```mermaid
flowchart LR
    kek["KEK, 32 bytes<br/>from SANCTUM_KEK<br/>never stored"]
    dek["DEK, 32 bytes<br/>fresh per reflection"]
    nonce["nonce, 12 bytes<br/>fresh per reflection"]
    pt["reflection text"]
    g1["AES-256-GCM seal"]
    g2["AES-256-GCM seal"]
    subgraph row["reflections row"]
        ct[("ciphertext")]
        edek[("encrypted_dek")]
        n[("nonce")]
    end

    pt --> g1
    dek -- key --> g1
    nonce --> g1
    g1 --> ct
    dek -- plaintext --> g2
    kek -- key --> g2
    nonce --> g2
    g2 --> edek
    nonce --> n
```

`crypto.Engine.Seal` (in `internal/crypto/engine.go`):

1. Reads a 32-byte DEK and a 12-byte nonce from `crypto/rand`.
2. Encrypts the plaintext with AES-256-GCM under the DEK.
3. Wraps the DEK with AES-256-GCM under the KEK, using the same nonce. This
   is safe because the two keys differ and the DEK is used only once
   (see [TD-001](docs/TECH_DEBT.md)).
4. Wipes the DEK and returns `(ciphertext, encryptedDEK, nonce)`.

`Open` does the reverse. Both GCM tags are checked, so any change to any of
the three stored values makes decryption fail. Only standard-library
primitives (`crypto/aes`, `crypto/cipher`, `crypto/rand`) are used.

### Threat model (short version)

The full table is in [`docs/rfc.md` section 6](docs/rfc.md). In short:

| Attacker can... | Result |
|---|---|
| Read a database dump or backup | Cannot read any reflection. Can see how many exist, their `day` and `created_at`, and the exact length of each text (GCM does not hide length). |
| Change bytes in `nonce`, `encrypted_dek` or `ciphertext` | Detected. The read fails with a 500, and a list that includes the row fails as a whole, so the API never returns data that did not authenticate. |
| Write to the database freely | **Not fully detected.** An envelope is not bound to its row (no associated data), so a whole envelope can be copied to another row, or `day`/`created_at` changed, without failing decryption. Rows can be deleted or an old backup restored. See [TD-004](docs/TECH_DEBT.md). |
| Read the server's environment or memory | Game over: the KEK decrypts everything. The DEK is wiped after use, but Go cannot guarantee that no other copy remains in memory. |
| Sniff the network | The server speaks plain HTTP. Run it behind a TLS proxy; the compose file binds to `127.0.0.1` only. |
| Guess the API token | One pre-shared bearer token, compared in constant time. There is no rate limiting yet. |

Other limits from the RFC: no key rotation in V1 (rotating the KEK would
mean re-wrapping every `encrypted_dek`), and a lost KEK means all data is
unrecoverable. The KEK encrypts with random 96-bit nonces, which NIST SP
800-38D limits to about 2^32 wraps per key. A daily journal will not
come close.

## API

All `/v1/reflections` routes need `Authorization: Bearer $SANCTUM_API_TOKEN`.

| Method | Path | Success | Errors |
|---|---|---|---|
| `POST` | `/v1/reflections` with `{"content": "..."}` | `201` + reflection | `400 invalid_input`, `401` |
| `GET` | `/v1/reflections[?day=YYYY-MM-DD]` | `200` + `{"reflections": [...], "count": N}` | `400`, `401` |
| `GET` | `/v1/reflections/{id}` | `200` + reflection | `400`, `401`, `404 not_found` |
| `GET` | `/v1/health`, `/health` | `200` (no auth) | |

Errors look like `{"error": "not_found", "message": "reflection not found"}`.
Internal errors are logged on the server and returned only as `internal`.
`PUT`, `PATCH` and `DELETE` return `405`.

Example session (real output from a local run):

```console
$ curl -s -X POST localhost:8080/v1/reflections -H "Authorization: Bearer $SANCTUM_API_TOKEN" \
    -d '{"content":"Today I understood that patience is not passive."}'
{"id":"48379f4b-16c3-44ea-b368-fe693747fbea","day":"2026-09-29","content":"Today I understood that patience is not passive.","created_at":"2026-09-29T18:18:53.949798Z"}

$ curl -s localhost:8080/v1/reflections/00000000-0000-0000-0000-000000000000 -H "Authorization: Bearer $SANCTUM_API_TOKEN"
{"error":"not_found","message":"reflection not found"}

$ curl -s -X POST localhost:8080/v1/reflections -d '{"content":"x"}'
{"error":"unauthorized","message":"missing or invalid API token"}
```

## Running it

Requirements: Go 1.26+, and Docker for the Postgres parts.

```sh
eval "$(make keys)"   # exports a fresh SANCTUM_KEK and SANCTUM_API_TOKEN
make up               # docker compose: Postgres 16 + Sanctum on 127.0.0.1:8080
```

Keep the KEK somewhere safe: without it, nothing stored can be decrypted.

To run the binary directly against your own Postgres:

```sh
export DATABASE_URL="postgres://user:pass@localhost:5432/sanctum?sslmode=disable"
eval "$(make keys)"
make run
```

| Variable | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | yes | Postgres connection string |
| `SANCTUM_KEK` | yes | Base64 of 32 random bytes (`openssl rand -base64 32`) |
| `SANCTUM_API_TOKEN` | yes | At least 32 characters (`openssl rand -hex 32`) |
| `SANCTUM_ADDR` | no | Listen address, default `:8080` |

On startup the server applies the embedded schema in `migrations/`
(idempotent), and on `SIGINT`/`SIGTERM` it drains in-flight requests
before exiting.

## Testing

```sh
make test              # unit tests, race detector; Postgres tests are skipped
make test-integration  # everything, against a throwaway Postgres container
make lint              # go vet, gofmt, gosec, govulncheck
```

What is covered:

- `internal/crypto`: round trip for empty, unicode, binary and 1 MiB
  inputs; a bit flip or truncation in every part of the envelope; wrong
  KEK; mixing parts of two envelopes; no repeated nonce or DEK over 1000
  seals; bad nonce lengths return an error instead of panicking; and an
  independent decryption with the standard library that checks the
  construction matches the RFC.
- `internal/service`: encrypt-then-store and fetch-then-decrypt with the
  real engine, UTC day derivation, tampered rows, not-found.
- `internal/handler`: every route and error code, the auth matrix, no
  internal error text in responses, no log injection through the URL.
- `internal/db` (needs `SANCTUM_TEST_DATABASE_URL`): byte-exact storage,
  day filter and ordering, duplicate ids rejected, malformed envelopes
  rejected by the schema, and a raw-row check that no plaintext is stored.

CI (`.github/workflows/ci.yml`) runs all of the above on Go 1.26 and 1.27
with a Postgres service, runs gosec and govulncheck, and brings up the
compose stack to create and read a reflection over HTTP.

## Layout

```
cmd/server/          main.go: config, wiring, HTTP server, graceful shutdown
internal/config/     environment variables -> Config
internal/crypto/     AES-256-GCM envelope encryption (Engine)
internal/db/         PostgresRepository, Open, Migrate
internal/domain/     Envelope, Reflection, ReflectionOutput, ErrNotFound
internal/handler/    HTTP handlers and middleware
internal/service/    ReflectionService and the Encryptor/Repository interfaces
migrations/          SQL schema, embedded into the binary
docs/                RFC, architecture, domain, tech-debt registry
```
