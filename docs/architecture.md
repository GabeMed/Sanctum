# Sanctum — System Architecture

## Design Principles

1. **Minimum viable layers.** Every layer must earn its place. No passthroughs.
2. **Dependencies flow inward.** The Handler depends on the Service. The Service
   depends on interfaces for Crypto and Storage. Nothing depends on the Handler.
3. **Interfaces at the consumer, not the producer.** The Service defines what it
   needs. The infrastructure implements it.

## System Diagram

```
                    ┌──────────────────────────────────┐
                    │           CLIENT                  │
                    │      (curl / Postman / CLI)       │
                    └──────────────┬───────────────────┘
                                   │
                          Plaintext JSON over TLS
                          Authorization: Bearer <token>
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                      HTTP HANDLER LAYER                         │
│                    (internal/handler)                            │
│                                                                 │
│  ReflectionHandler                                              │
│  ├── POST /v1/reflections  → handleCreate()                    │
│  ├── GET  /v1/reflections  → handleList()                      │
│  └── GET  /v1/reflections/{id} → handleGetByID()               │
│                                                                 │
│  Responsibilities:                                              │
│  - Parse HTTP request (JSON deserialization)                    │
│  - Validate input (content not empty, day format valid)         │
│  - Call the Service                                             │
│  - Format HTTP response (JSON serialization)                   │
│  - Map errors to status codes (never leak internals)           │
│                                                                 │
│  Knows about: HTTP, JSON, the Service interface                │
│  Knows NOTHING about: AES-GCM, SQL, Postgres                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                  ReflectionInput / ReflectionOutput structs
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      SERVICE LAYER                              │
│                   (internal/service)                             │
│                                                                 │
│  ReflectionService                                              │
│  ├── Create(ctx, content string) → (ReflectionOutput, error)   │
│  ├── ListByDay(ctx, day *time.Time) → ([]ReflectionOutput, error)│
│  └── GetByID(ctx, id uuid.UUID) → (ReflectionOutput, error)    │
│                                                                 │
│  Dependencies (injected via constructor):                       │
│  ├── Encryptor interface  (encrypt/decrypt)                    │
│  └── Repository interface (save/find)                          │
│                                                                 │
│  Responsibilities:                                              │
│  - Orchestrate: encrypt → store (Create)                       │
│  - Orchestrate: fetch → decrypt (Read)                         │
│  - Apply business rules (derive day from current time, etc.)   │
│                                                                 │
│  Knows about: domain types, what Encryptor and Repo CAN do     │
│  Knows NOTHING about: HOW encryption works, HOW SQL works      │
└────────────┬──────────────────────────────┬─────────────────────┘
             │                              │
             ▼                              ▼
┌────────────────────────────┐ ┌──────────────────────────────────┐
│      ENCRYPTOR             │ │         REPOSITORY               │
│   (internal/crypto)        │ │      (internal/storage)          │
│                            │ │                                  │
│  Interface:                │ │  Interface:                      │
│  ├── Encrypt(plaintext)    │ │  ├── Save(ctx, Reflection)       │
│  │   → (Envelope, error)   │ │  │   → error                     │
│  └── Decrypt(envelope)     │ │  ├── FindByDay(ctx, day)         │
│      → (plaintext, error)  │ │  │   → ([]Reflection, error)     │
│                            │ │  └── FindByID(ctx, id)           │
│  Implementation:           │ │      → (*Reflection, error)      │
│  AES-256-GCM               │ │                                  │
│  - Fresh DEK per operation │ │  Implementation:                 │
│  - KEK from config         │ │  PostgresRepository              │
│  - 12-byte random nonce    │ │  - Raw SQL (no ORM)              │
│                            │ │  - database/sql + pgx driver     │
│  Already built. 100% tests.│ │                                  │
└────────────────────────────┘ └───────────────┬──────────────────┘
                                               │
                                          Raw SQL
                                               │
                                               ▼
                               ┌───────────────────────────┐
                               │       POSTGRESQL           │
                               │                           │
                               │  reflections table        │
                               │  ├── id (UUID PK)         │
                               │  ├── day (DATE, indexed)  │
                               │  ├── nonce (BYTEA)        │
                               │  ├── encrypted_dek (BYTEA)│
                               │  ├── ciphertext (BYTEA)   │
                               │  └── created_at (TIMESTAMPTZ)│
                               └───────────────────────────┘
```

## Request Lifecycle: Create Reflection

```
1. Client sends POST /v1/reflections with { "content": "..." }
2. Auth middleware validates the Bearer token → 401 if invalid
3. Handler parses JSON → 400 if malformed
4. Handler calls Service.Create(ctx, content)
5. Service generates day = time.Now().UTC().Truncate(24h)
6. Service calls Encryptor.Encrypt(content)
   a. CryptoEngine generates fresh 256-bit DEK
   b. CryptoEngine generates 12-byte nonce
   c. CryptoEngine encrypts content with DEK via AES-256-GCM
   d. CryptoEngine encrypts DEK with KEK via AES-256-GCM
   e. Returns Envelope{Nonce, EncryptedDEK, Ciphertext}
7. Service calls Repository.Save(ctx, Reflection{...})
   a. PostgresRepository executes INSERT INTO reflections (...)
   b. Returns the generated UUID
8. Service builds ReflectionOutput with plaintext content + metadata
9. Handler serializes to JSON, writes 201 Created
```

## Request Lifecycle: Read Reflections by Day

```
1. Client sends GET /v1/reflections?day=2026-03-04
2. Auth middleware validates token
3. Handler parses query param → defaults to all if no day provided
4. Handler calls Service.ListByDay(ctx, day)
5. Service calls Repository.FindByDay(ctx, day)
   a. PostgresRepository executes SELECT ... WHERE day = $1
   b. Returns []Reflection (encrypted)
6. For each reflection, Service calls Encryptor.Decrypt(envelope)
   a. CryptoEngine decrypts DEK with KEK
   b. CryptoEngine decrypts ciphertext with DEK + nonce
   c. Returns plaintext
7. Service builds []ReflectionOutput with plaintext content
8. Handler serializes to JSON, writes 200 OK
```

## Project Structure

```
sanctum/
├── cmd/
│   └── sanctum/
│       └── main.go              # Entry point. Wires everything.
├── internal/
│   ├── config/
│   │   └── config.go            # Reads env vars, builds Config struct
│   ├── crypto/
│   │   ├── engine.go            # AES-256-GCM envelope encryption [DONE]
│   │   └── engine_test.go       # 100% coverage [DONE]
│   ├── domain/
│   │   └── reflection.go        # Reflection struct, Envelope struct
│   ├── handler/
│   │   ├── middleware.go         # Auth, logging, recovery, request ID
│   │   ├── reflection.go        # HTTP handlers for /v1/reflections
│   │   └── reflection_test.go
│   ├── service/
│   │   ├── interfaces.go        # Encryptor + Repository interfaces
│   │   ├── reflection.go        # ReflectionService (the orchestrator)
│   │   └── reflection_test.go
│   └── storage/
│       ├── postgres.go           # PostgresRepository implementation
│       └── postgres_test.go
├── migrations/
│   ├── 000001_create_reflections.up.sql
│   └── 000001_create_reflections.down.sql
├── docs/
│   ├── architecture.md           # This document
│   ├── rfc.md                    # The RFC
│   └── domain.md                 # Domain document
├── docker-compose.yml
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## Interfaces (The Contracts)

The Service layer defines two interfaces. This is idiomatic Go:
interfaces are defined where they are CONSUMED, not where they are
implemented.

```go
// internal/service/interfaces.go

// Encryptor defines what the Service needs from the crypto layer.
type Encryptor interface {
    Encrypt(plaintext []byte) (*domain.Envelope, error)
    Decrypt(envelope *domain.Envelope) ([]byte, error)
}

// Repository defines what the Service needs from the storage layer.
type Repository interface {
    Save(ctx context.Context, r *domain.Reflection) error
    FindByDay(ctx context.Context, day time.Time) ([]domain.Reflection, error)
    FindByID(ctx context.Context, id uuid.UUID) (*domain.Reflection, error)
}
```

## Dependency Injection (main.go)

```
main.go reads config
  → creates DB connection pool
  → creates PostgresRepository (implements Repository)
  → creates CryptoEngine with KEK from config (implements Encryptor)
  → creates ReflectionService with Repository + Encryptor
  → creates ReflectionHandler with Service
  → creates HTTP server with Handler + Middleware
  → starts listening
```

No framework. No DI container. Just constructors and interfaces.
