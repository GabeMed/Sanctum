# Technical Debt Registry

> Decisions deferred for simplicity. Each item must have a justification and a trigger condition for when to revisit.

---

## TD-001: Single Nonce for Dual GCM Operations

**Status:** Accepted
**Date:** 2026-02-27
**Component:** `internal/crypto/engine.go`

### Context

The `Seal()` function uses the same 12-byte nonce for two AES-GCM operations:
1. Encrypting plaintext with the DEK
2. Encrypting the DEK with the masterKey

### Decision

**Keep single nonce** — mathematically safe because the keys are different.

AES-GCM's security requirement is: *never reuse the same (key, nonce) pair*. Since:
- `(DEK, nonce)` is unique per call (DEK is randomly generated)
- `(masterKey, nonce)` uses a random nonce each call

There is no cryptographic vulnerability.

### Trade-offs

| Single Nonce (chosen) | Dual Nonce (deferred) |
|-----------------------|-----------------------|
| Fewer random bytes | Defense in depth |
| Simpler code | Cleaner audit trail |
| Mathematically correct | Conventional pattern |

### Revisit Trigger

- [ ] External security audit requires separate nonces
- [ ] Key derivation changes such that both operations share key material
- [ ] Compliance requirement (SOC2, PCI-DSS) mandates nonce separation

### Migration Path

If revisited:
1. Generate second nonce: `dekNonce := make([]byte, gcm.NonceSize())`
2. Return both nonces or concatenate into envelope format
3. Update `Open()` to parse both nonces

---

## TD-002: Three-Value Return vs. Opaque Envelope

**Status:** Accepted
**Date:** 2026-02-27
**Component:** `internal/crypto/engine.go`

### Context

`Seal()` returns `(ciphertext, encryptedDEK, nonce)` as three separate values rather than a single opaque `[]byte` envelope.

### Decision

**Keep three-value return** — simpler for initial implementation and learning.

### Trade-offs

| Three Values (chosen) | Opaque Envelope (deferred) |
|-----------------------|----------------------------|
| Caller manages association | Single value, no mistakes |
| Flexible storage | Versioned format for future |
| Explicit structure | Algorithm agility built-in |

### Revisit Trigger

- [ ] Adding algorithm versioning (e.g., switching from AES-GCM to XChaCha20-Poly1305)
- [ ] Caller mistakes in associating ciphertext/DEK/nonce
- [ ] Need for key ID or metadata in the envelope

### Migration Path

If revisited, implement envelope format:
```
[version:1][nonce:12][encryptedDEK:48][ciphertext:N]
```

---

## TD-003: Engine.go is tight coupled with GCM

**Status:** Accepted
**Date:** 2026-03-01
**Component:** `internal/crypto/engine.go`

---

## TD-004: Envelope is not bound to its row

**Status:** Accepted
**Date:** 2026-09-29
**Component:** `internal/crypto/engine.go`, `internal/service/reflection.go`

### Context

`Seal()` passes no associated data (AAD) to AES-GCM. The GCM tags protect
`nonce`, `encrypted_dek` and `ciphertext` against modification, but nothing
ties an envelope to the row it is stored in.

### Consequence

Someone with write access to the database can copy a whole envelope into
another row, or change a row's `day` / `created_at`, and decryption still
succeeds. Deleting rows or restoring an old backup is also not detected.
Reading the content still requires the KEK.

### Decision

**Keep for V1.** The RFC threat model targets database dumps and disk
theft (read access), which this design covers. Write access to the
database is closer to server compromise, which V1 does not defend against.

### Revisit Trigger

- [ ] The database is operated by someone other than the KEK holder
- [ ] Opaque envelope format from TD-002 is introduced (natural place to add it)

### Migration Path

1. Pass `id || day` as AAD to both GCM calls (`Seal(nil, nonce, x, aad)`).
2. Add a `version` byte (TD-002) so rows written without AAD stay readable.
3. Re-seal old rows lazily on read, or in a one-off job.
