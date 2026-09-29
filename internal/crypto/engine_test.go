package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/GabeMed/Sanctum/internal/domain"
)

// gcmTagSize is the authentication tag AES-GCM appends to every ciphertext.
const gcmTagSize = 16

func newTestEngine(t *testing.T) (*Engine, []byte) {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	engine, err := NewEngine(key)
	if err != nil {
		t.Fatalf("Failed to create a new engine: %v", err)
	}
	return engine, key
}

func TestEngine_InvalidKey(t *testing.T) {
	// Arrange: Create a 31-byte key
	invalidKey := make([]byte, 31)

	// Act: Attempt to create the engine
	_, err := NewEngine(invalidKey)

	// Assert: Check if the error matches our expected contract
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}
}

func TestEngine_InvalidKeySizes(t *testing.T) {
	// AES-128 (16) and AES-192 (24) are valid AES keys but not AES-256.
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		if _, err := NewEngine(make([]byte, size)); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("key size %d: expected ErrInvalidKeySize, got %v", size, err)
		}
	}
}

func TestEngine_RoundTrip(t *testing.T) {
	mockKey := make([]byte, 32)
	mockPlaintext := []byte("Forgive me, Father, for I have sinned")

	engine, err := NewEngine(mockKey)
	if err != nil {
		t.Fatalf("Failed to create a new engine: %v", err)
	}

	mockCiphertext, mockEncryptedDEK, mockNonce, err := engine.Seal(mockPlaintext)
	if err != nil {
		t.Fatalf("Engine failed to seal the message: %v", err)
	}

	mockDecryptedtext, err := engine.Open(mockCiphertext, mockEncryptedDEK, mockNonce)
	if err != nil {
		t.Fatalf("Engine failed to open the cipher text: %v", err)
	}

	if !bytes.Equal(mockPlaintext, mockDecryptedtext) {
		t.Errorf("Falied the round trip expected %v, got %v", mockPlaintext, mockDecryptedtext)
	}
}

func TestEngine_RoundTripSizes(t *testing.T) {
	engine, _ := newTestEngine(t)

	large := make([]byte, 1<<20)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":   {},
		"one":     []byte("a"),
		"unicode": []byte("Não temas, porque eu sou contigo"),
		"binary":  {0x00, 0xff, 0x00, 0x10},
		"1MiB":    large,
	}
	for name, plaintext := range cases {
		t.Run(name, func(t *testing.T) {
			ciphertext, encryptedDEK, nonce, err := engine.Seal(plaintext)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			// Envelope sizes: ciphertext = plaintext + tag, wrapped DEK = key + tag.
			if got, want := len(ciphertext), len(plaintext)+gcmTagSize; got != want {
				t.Errorf("ciphertext length = %d, want %d", got, want)
			}
			if got, want := len(encryptedDEK), KeySize+gcmTagSize; got != want {
				t.Errorf("encryptedDEK length = %d, want %d", got, want)
			}
			if len(nonce) != NonceSize {
				t.Errorf("nonce length = %d, want %d", len(nonce), NonceSize)
			}

			got, err := engine.Open(ciphertext, encryptedDEK, nonce)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("round trip mismatch")
			}
		})
	}
}

func TestEngine_Tamper(t *testing.T) {
	mockKey := make([]byte, 32)
	mockPlaintext := []byte("Forgive me, Father, for I have sinned")

	engine, err := NewEngine(mockKey)
	if err != nil {
		t.Fatalf("Failed to create a new engine: %v", err)
	}

	mockCiphertext, mockEncryptedDEK, mockNonce, err := engine.Seal(mockPlaintext)
	if err != nil {
		t.Fatalf("Engine failed to seal the message: %v", err)
	}

	mockCiphertext[0] ^= 0xff

	mockDecryptedtext, err := engine.Open(mockCiphertext, mockEncryptedDEK, mockNonce)
	if err == nil {
		t.Errorf("CRITICAL engine failed to authenticate. Expected err got %v", mockDecryptedtext)
	}
}

// TestEngine_TamperEveryPart flips a single bit in each part of the envelope,
// including the GCM tag at the end of each ciphertext, and truncates each part.
func TestEngine_TamperEveryPart(t *testing.T) {
	engine, _ := newTestEngine(t)
	plaintext := []byte("Forgive me, Father, for I have sinned")

	type envelope struct{ ciphertext, encryptedDEK, nonce []byte }
	fresh := func(t *testing.T) envelope {
		c, d, n, err := engine.Seal(plaintext)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		return envelope{c, d, n}
	}

	cases := map[string]func(e *envelope){
		"ciphertext first byte":   func(e *envelope) { e.ciphertext[0] ^= 0x01 },
		"ciphertext tag":          func(e *envelope) { e.ciphertext[len(e.ciphertext)-1] ^= 0x01 },
		"ciphertext truncated":    func(e *envelope) { e.ciphertext = e.ciphertext[:len(e.ciphertext)-1] },
		"ciphertext extended":     func(e *envelope) { e.ciphertext = append(e.ciphertext, 0) },
		"encryptedDEK first byte": func(e *envelope) { e.encryptedDEK[0] ^= 0x01 },
		"encryptedDEK tag":        func(e *envelope) { e.encryptedDEK[len(e.encryptedDEK)-1] ^= 0x01 },
		"encryptedDEK truncated":  func(e *envelope) { e.encryptedDEK = e.encryptedDEK[:KeySize] },
		"nonce bit flip":          func(e *envelope) { e.nonce[0] ^= 0x01 },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			e := fresh(t)
			tamper(&e)
			if got, err := engine.Open(e.ciphertext, e.encryptedDEK, e.nonce); err == nil {
				t.Fatalf("CRITICAL: tampered envelope opened: %q", got)
			}
		})
	}
}

func TestEngine_WrongMasterKey(t *testing.T) {
	engineA, _ := newTestEngine(t)
	engineB, _ := newTestEngine(t)

	ciphertext, encryptedDEK, nonce, err := engineA.Seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engineB.Open(ciphertext, encryptedDEK, nonce); err == nil {
		t.Fatal("CRITICAL: envelope opened with a different master key")
	}
}

// TestEngine_MixedEnvelopes checks that parts of two different envelopes
// cannot be combined: each ciphertext is bound to its own DEK.
func TestEngine_MixedEnvelopes(t *testing.T) {
	engine, _ := newTestEngine(t)

	cA, dA, nA, err := engine.Seal([]byte("reflection A"))
	if err != nil {
		t.Fatal(err)
	}
	cB, dB, nB, err := engine.Seal([]byte("reflection B"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := engine.Open(cB, dA, nA); err == nil {
		t.Error("ciphertext B opened with DEK/nonce of A")
	}
	if _, err := engine.Open(cA, dB, nB); err == nil {
		t.Error("ciphertext A opened with DEK/nonce of B")
	}
	if _, err := engine.Open(cA, dA, nB); err == nil {
		t.Error("envelope A opened with nonce of B")
	}
}

// TestEngine_FreshDEKAndNonce checks that sealing the same plaintext twice
// never produces the same nonce, wrapped DEK or ciphertext.
func TestEngine_FreshDEKAndNonce(t *testing.T) {
	engine, _ := newTestEngine(t)
	plaintext := []byte("same words every day")

	seenNonces := map[string]bool{}
	seenDEKs := map[string]bool{}
	seenCiphertexts := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c, d, n, err := engine.Seal(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if seenNonces[string(n)] || seenDEKs[string(d)] || seenCiphertexts[string(c)] {
			t.Fatalf("repeated envelope component at iteration %d", i)
		}
		seenNonces[string(n)] = true
		seenDEKs[string(d)] = true
		seenCiphertexts[string(c)] = true
	}
}

// TestEngine_MalformedNonce checks that Open returns an error instead of
// panicking (cipher.AEAD.Open panics on a wrong nonce length).
func TestEngine_MalformedNonce(t *testing.T) {
	engine, _ := newTestEngine(t)
	ciphertext, encryptedDEK, _, err := engine.Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, NonceSize - 1, NonceSize + 1, 24} {
		_, err := engine.Open(ciphertext, encryptedDEK, make([]byte, size))
		if !errors.Is(err, ErrMalformedEnvelope) {
			t.Errorf("nonce size %d: expected ErrMalformedEnvelope, got %v", size, err)
		}
	}
	if _, err := engine.Open(ciphertext, encryptedDEK, nil); !errors.Is(err, ErrMalformedEnvelope) {
		t.Errorf("nil nonce: expected ErrMalformedEnvelope, got %v", err)
	}
}

// TestEngine_KeyIsCopied checks that wiping the caller's key slice does not
// change the engine's master key.
func TestEngine_KeyIsCopied(t *testing.T) {
	engine, key := newTestEngine(t)
	ciphertext, encryptedDEK, nonce, err := engine.Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	zeroBytes(key)
	if _, err := engine.Open(ciphertext, encryptedDEK, nonce); err != nil {
		t.Fatalf("Open after wiping caller key: %v", err)
	}
}

// TestEngine_ConstructionMatchesDesign decrypts a sealed envelope using only
// the standard library, following the steps in docs/rfc.md section 5:
// unwrap the DEK with AES-256-GCM(KEK, nonce), then decrypt the content with
// AES-256-GCM(DEK, nonce).
func TestEngine_ConstructionMatchesDesign(t *testing.T) {
	engine, kek := newTestEngine(t)
	plaintext := []byte("In principio erat Verbum")

	ciphertext, encryptedDEK, nonce, err := engine.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	open := func(key, sealed []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		out, err := gcm.Open(nil, nonce, sealed, nil)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	dek := open(kek, encryptedDEK)
	if len(dek) != KeySize {
		t.Fatalf("DEK length = %d, want %d", len(dek), KeySize)
	}
	if bytes.Equal(dek, kek) {
		t.Fatal("DEK equals KEK")
	}
	if got := open(dek, ciphertext); !bytes.Equal(got, plaintext) {
		t.Fatalf("manual decryption = %q, want %q", got, plaintext)
	}
}

func TestEngine_EncryptDecrypt(t *testing.T) {
	engine, _ := newTestEngine(t)
	plaintext := []byte("Envelope adapter")

	envelope, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := engine.Decrypt(envelope)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q, want %q", got, plaintext)
	}

	envelope.Ciphertext[0] ^= 0x01
	if _, err := engine.Decrypt(envelope); err == nil {
		t.Fatal("CRITICAL: tampered envelope decrypted")
	}

	if _, err := engine.Decrypt(nil); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("Decrypt(nil): expected ErrMalformedEnvelope, got %v", err)
	}
	if _, err := engine.Decrypt(&domain.Envelope{}); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("Decrypt(empty): expected ErrMalformedEnvelope, got %v", err)
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	zeroBytes(b)
	if !bytes.Equal(b, make([]byte, 4)) {
		t.Fatalf("zeroBytes left %v", b)
	}
}
