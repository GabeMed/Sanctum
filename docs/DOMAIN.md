# Sanctum — Domain Document

## What Is Sanctum?

Sanctum is a single-tenant, append-only encrypted vault for daily reflections.
A user writes a reflection. The server encrypts it and stores it.
The user can retrieve reflections by day or by ID. The server decrypts
and returns the plaintext. Reflections are immutable — once written,
they cannot be edited or deleted.

## Entities

### Reflection

The single core entity of the system.

| Field         | Type        | Nullable | Notes                                         |
|---------------|-------------|----------|-----------------------------------------------|
| id            | UUID        | NOT NULL | Primary key, generated server-side             |
| day           | DATE        | NOT NULL | Plaintext. Queryable. The date of the entry    |
| nonce         | BYTEA       | NOT NULL | Plaintext. Required by AES-GCM for decryption |
| encrypted_dek | BYTEA       | NOT NULL | DEK encrypted by the KEK (envelope encryption) |
| ciphertext    | BYTEA       | NOT NULL | Reflection content encrypted by the DEK        |
| created_at    | TIMESTAMPTZ | NOT NULL | Timestamp of creation                          |

**Why `day` is plaintext**: Postgres cannot search inside encrypted data.
To support "give me all reflections from March 15th," the date must be
stored as a queryable, indexed, plaintext column. This means an attacker
with database access can see THAT a reflection exists on a given day,
but cannot read WHAT it says. This is an acceptable tradeoff for V1.

**Why no `updated_at`**: Reflections are immutable. There are no updates.

## Operations

### Create Reflection

| Direction | Shape |
|-----------|-------|
| Request   | `{ "content": "plaintext string" }` |
| Response  | `201 Created` — `{ "id": "uuid", "day": "YYYY-MM-DD", "content": "plaintext string", "created_at": "RFC3339 timestamp" }` |

The server receives plaintext, encrypts it (generating a DEK, encrypting the content,
wrapping the DEK with the KEK), stores the encrypted form, and returns the original
plaintext alongside the metadata to confirm creation.

### List Reflections by Day

| Direction | Shape |
|-----------|-------|
| Request   | `GET /reflections?day=YYYY-MM-DD` (day is optional; if omitted, returns all) |
| Response  | `200 OK` — `{ "reflections": [ { "id", "day", "content", "created_at" } ], "count": N }` |

The server queries by the plaintext `day` column, decrypts each reflection,
and returns plaintext content to the client.

### Get Reflection by ID

| Direction | Shape |
|-----------|-------|
| Request   | `GET /reflections/{id}` |
| Response  | `200 OK` — `{ "id", "day", "content", "created_at" }` |

The server fetches by primary key, decrypts, and returns plaintext.

## Boundaries

### What Sanctum IS

- A single-tenant encrypted storage engine
- An append-only log (create and read only)
- A server that owns encryption/decryption (Model A — server-side encryption at rest)
- An API that speaks plaintext JSON to clients over TLS

### What Sanctum IS NOT (V1)

- Not a multi-user system (no auth beyond a pre-shared API token)
- Not a client-side encryption system (E2E encryption is a V2 consideration)
- Not a general-purpose storage platform (future extensibility is noted but not built)
- Not a system that supports editing or deleting reflections
- Not a system with a UI or frontend
- Not a system with key rotation (V2)
