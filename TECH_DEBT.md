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
