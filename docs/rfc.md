# RFC: Sanctum

- **RFC Number:** 001 
- **Date:** 2026-03-04
- **Author:** Gabriel Medeiros
- **Status:** Complete
- **Targeted Release:** V1

---

## 1. The Problem

I want to journal daily — reflections, prayers, confessions — but no existing
tool provides the combination of simplicity and cryptographic safety I require.
Cloud journals can be read by the provider. Local text files can be read by
anyone with disk access. Sanctum is a personal, sacred vault: an encrypted
append-only log where the contents are protected at rest by envelope encryption,
and only the operator of the system can read them.

"Sanctum" — Latin for "that which is holy." The code is the cathedral.
The reflections are the prayers within.

---

## 2. Constraints (Non-Functional Requirements)

| Constraint            | Target          | How It Will Be Validated              |
|-----------------------|-----------------|---------------------------------------|
| Response Latency      | < 50ms (p95)    | Load testing with K6 at Phase 5       |
| Availability          | 99.9% uptime    | Health check monitoring via Grafana   |
| Test Coverage         | 100% unit tests | CI pipeline fails below threshold     |
| Encryption Standard   | AES-256-GCM     | Crypto module with full test coverage |
| Container Image Size  | < 20MB          | Multi-stage Dockerfile, distroless    |
| Data Durability       | Zero data loss   | Postgres WAL + graceful shutdown      |

---

## 3. API Contract — "The Liturgy of Routes"

All endpoints are prefixed with `/v1`.
All request and response bodies are `application/json`.
Authentication is via a pre-shared token in the `Authorization` header.

### POST /v1/reflections — "The Confession"

Write a new reflection. The content is received as plaintext, encrypted
at rest by the server, and the plaintext is echoed back as confirmation.

**Request:**
```json
{
  "content": "Today I understood that patience is not passive..."
}
```

**Response (201 Created):**
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "day": "2026-03-04",
  "content": "Today I understood that patience is not passive...",
  "created_at": "2026-03-04T08:30:00Z"
}
```

### GET /v1/reflections — "The Lectio"

Read the reflections. Optionally filter by day.
The server decrypts each reflection before returning plaintext.

**Request:**
```
GET /v1/reflections?day=2026-03-04
```

**Response (200 OK):**
```json
{
  "reflections": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "day": "2026-03-04",
      "content": "Today I understood that patience is not passive...",
      "created_at": "2026-03-04T08:30:00Z"
    }
  ],
  "count": 1
}
```

### GET /v1/reflections/{id} — "The Meditation"

Retrieve a single reflection by its unique identifier.

**Request:**
```
GET /v1/reflections/f47ac10b-58cc-4372-a567-0e02b2c3d479
```

**Response (200 OK):**
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "day": "2026-03-04",
  "content": "Today I understood that patience is not passive...",
  "created_at": "2026-03-04T08:30:00Z"
}
```

### GET /v1/health — "The Pulse"

Health check. Returns the service status.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2026-03-04T08:30:00Z"
}
```

### Error Responses — "The Silence"

The server never leaks internal details. All errors follow this format:

```json
{ "error": "error_code", "message": "human-readable description" }
```

| Status | Code              | When                                      |
|--------|-------------------|-------------------------------------------|
| 400    | `invalid_input`   | Missing or malformed request body         |
| 401    | `unauthorized`    | Missing or invalid API token              |
| 404    | `not_found`       | Reflection ID does not exist              |
| 500    | `internal`        | Unexpected server error (details logged, never returned) |

---

## 4. Data Model

### The `reflections` Table

| Field         | Type        | Nullable | Notes                                          |
|---------------|-------------|----------|-------------------------------------------------|
| id            | UUID        | NOT NULL | Primary key, generated via `gen_random_uuid()`  |
| day           | DATE        | NOT NULL | Plaintext date for queryability                 |
| nonce         | BYTEA       | NOT NULL | AES-GCM nonce (12 bytes), stored in plaintext   |
| encrypted_dek | BYTEA       | NOT NULL | Data Encryption Key, wrapped by the KEK         |
| ciphertext    | BYTEA       | NOT NULL | Reflection content, encrypted by the DEK        |
| created_at    | TIMESTAMPTZ | NOT NULL | Defaults to `now()`                             |

**Indexes:**
- `idx_reflections_day` on `(day)` — primary query pattern
- `idx_reflections_day_created` on `(day, created_at)` — ordering within a day

**Design Decisions:**
- `day` is plaintext because Postgres cannot query inside encrypted columns.
  The tradeoff: an attacker with DB access can see that reflections exist on a
  given date, but cannot read their content. This is acceptable for V1.
- `nonce` is plaintext because it is not a secret. It is a public parameter
  required by AES-GCM for decryption. Encrypting it would create a circular
  dependency (you would need a nonce to decrypt the nonce).
- No `updated_at` column. Reflections are immutable. Append-only by design.

---

## 5. Encryption Design

### Architecture: Server-Side Envelope Encryption (Model A)

The server is the trusted encryption boundary. Clients send and receive
plaintext over TLS. The server encrypts before writing to storage and
decrypts before returning to the client. The client never sees ciphertext.

### Key Hierarchy

```
┌─────────────────────────────────────┐
│  KEK (Key Encryption Key)           │
│  - AES-256 key (32 bytes)           │
│  - Loaded from environment variable │
│  - One per deployment               │
│  - Never stored in the database     │
└──────────────┬──────────────────────┘
               │ wraps/unwraps
               ▼
┌─────────────────────────────────────┐
│  DEK (Data Encryption Key)          │
│  - AES-256 key (32 bytes)           │
│  - Generated fresh for EACH reflection │
│  - Encrypted by KEK before storage  │
│  - Stored in `encrypted_dek` column │
└──────────────┬──────────────────────┘
               │ encrypts/decrypts
               ▼
┌─────────────────────────────────────┐
│  Reflection Content (plaintext)     │
│  - Encrypted by DEK using AES-GCM  │
│  - Stored in `ciphertext` column    │
│  - Nonce stored in `nonce` column   │
└─────────────────────────────────────┘
```

### Encryption Flow (Create)

```
1. Client sends plaintext content over TLS
2. Server generates a fresh 256-bit DEK (crypto/rand)
3. Server generates a 12-byte nonce (crypto/rand)
4. Server encrypts plaintext with DEK using AES-256-GCM → ciphertext
5. Server encrypts DEK with KEK using AES-256-GCM → encrypted_dek
6. Server writes (nonce, encrypted_dek, ciphertext, day) to Postgres
7. Server returns plaintext + metadata to client as confirmation
```

### Decryption Flow (Read)

```
1. Server reads (nonce, encrypted_dek, ciphertext) from Postgres
2. Server decrypts encrypted_dek with KEK → plaintext DEK
3. Server decrypts ciphertext with DEK + nonce → plaintext content
4. Server returns plaintext to client over TLS
5. Plaintext DEK is wiped from memory (zeroed)
```

### Why Envelope Encryption?

- **Blast radius reduction**: If a single DEK is compromised, only one
  reflection is exposed. The KEK and all other DEKs remain safe.
- **No re-encryption on key rotation (V2)**: When the KEK is rotated,
  you only re-wrap the DEKs (small, fast). You do not re-encrypt the
  actual content (large, slow).
- **Industry standard**: This is the same pattern used by AWS S3, Google
  Cloud Storage, and Azure Blob Storage for encryption at rest.

---

## 6. Threat Model

### What We Defend Against

| Threat                          | Mitigation                                    |
|---------------------------------|-----------------------------------------------|
| Database dump / disk theft      | Envelope encryption at rest. All content is AES-256-GCM encrypted. The KEK is not in the database. |
| Network eavesdropping           | TLS in transit. The client-server channel is encrypted at the transport layer. |
| Unauthorized API access         | Pre-shared API token in `Authorization` header, validated by middleware. |
| Single DEK compromise           | Each reflection has its own DEK. Blast radius = 1 reflection. |
| Internal error leakage          | Standardized error responses. Stack traces logged server-side only, never returned to client. |

### What We Do NOT Defend Against (V1)

| Threat                          | Status                                        |
|---------------------------------|-----------------------------------------------|
| Full server compromise (root)   | NOT mitigated. If an attacker has root access to the running server, they can read the KEK from the environment and decrypt everything. Mitigation: E2E encryption (V2). |
| KEK theft from environment      | NOT mitigated. The KEK is a single point of failure. Mitigation: KMS integration (V2). |
| Key rotation                    | NOT supported. If the KEK is compromised, all data must be re-encrypted manually. Mitigation: Automated key rotation (V2). |
| Brute force API access          | Partially mitigated by rate limiting (Phase 5). Full mitigation requires proper auth (V2). |

### Plaintext Metadata Tradeoff

The `day` and `created_at` columns are stored in plaintext. An attacker with
database access can determine:
- How many reflections exist
- On which dates reflections were written
- The timestamps of creation

An attacker CANNOT determine:
- The content of any reflection
- The length of the original plaintext (AES-GCM ciphertext length reveals approximate length — this is a known, accepted limitation)

This tradeoff is acceptable because the alternative (encrypting dates) would
require decrypting every row for any query, making the system unusable.

---

## 7. Testing & Validation Strategy

| Layer            | Method                        | Coverage Target |
|------------------|-------------------------------|-----------------|
| Crypto Engine    | Unit tests (table-driven)     | 100%            |
| Repository       | Unit tests (mocked interface) | 100%            |
| Service Layer    | Unit tests (mocked deps)      | 100%            |
| HTTP Handlers    | Unit tests (httptest)         | 100%            |
| End-to-End       | Integration test (docker-compose + real Postgres) | Happy path + error paths |
| Performance      | Load test (K6, 500-1000 req/s)| p95 < 50ms      |
| Security         | Static analysis (gosec)       | Zero findings   |

---

## 8. Dependencies & Risks

### Dependencies

| Dependency                | Purpose                          | Risk Level |
|---------------------------|----------------------------------|------------|
| Go standard library `crypto/aes`, `crypto/cipher` | AES-256-GCM implementation | Low — stdlib, well audited |
| `pgx` (PostgreSQL driver) | Database connectivity            | Low — industry standard    |
| `golang-migrate`          | Schema migrations                | Low — widely adopted       |
| PostgreSQL 15+            | Data persistence                 | Low — mature, proven       |

### Risks

| Risk                                  | Impact | Mitigation                          |
|---------------------------------------|--------|-------------------------------------|
| KEK loss (operator loses the key)     | TOTAL  | All data unrecoverable. Document backup procedures in runbook. |
| Nonce reuse                           | HIGH   | Fresh `crypto/rand` nonce per operation. AES-GCM allows ~2^32 encryptions per key before collision risk. Each DEK is used exactly once, so nonce reuse is structurally impossible. |
| Undetected data corruption            | MEDIUM | AES-GCM provides authenticated encryption. Tampered ciphertext fails decryption with an authentication error. |

---

## 9. Not in Scope (V1)

- User authentication and multi-tenancy (pre-shared token only)
- Client-side / end-to-end encryption (E2E is a V2 consideration)
- General-purpose encrypted storage platform (noted, not built)
- Editing or deleting reflections (append-only by design)
- Frontend or UI of any kind
- Key rotation or KEK management via KMS
- Search within encrypted content
- File attachments or non-text content

---

## 10. Decision

- **Decision Date**: _Pending review_
- **Outcome**: _Pending_
- **Comments**: _This RFC is the first formal architectural contract for Sanctum V1. All implementation must conform to the decisions documented here. Deviations require an RFC amendment._

---

## 11. References

- Kleppmann, M. _Designing Data-Intensive Applications_ — Ch. 1 (Reliability, Scalability, Maintainability)
- Google SRE Book — Ch. 4 (Service Level Objectives)
- NIST SP 800-38D — Recommendation for Block Cipher Modes: GCM
- Go standard library `crypto/cipher` documentation
- Google Cloud KMS: Envelope Encryption (conceptual reference for V2)
