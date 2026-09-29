package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/GabeMed/Sanctum/internal/domain"
)

// Key and nonce size constants for AES-256-GCM
const (
	KeySize   = 32 // AES-256 requires 32-byte keys
	NonceSize = 12 // GCM standard nonce size (96 bits)
)

var (
	ErrInvalidKeySize = errors.New("master key must be exactly 32 bytes (AES-256)")
	// ErrMalformedEnvelope is returned by Open when the envelope cannot be a
	// valid output of Seal (for example, a nonce of the wrong length).
	ErrMalformedEnvelope = errors.New("malformed envelope")
)

// Engine provides envelope encryption using AES-256-GCM.
// Each Seal operation generates a unique Data Encryption Key (DEK),
// encrypts the plaintext with the DEK, then wraps the DEK with the master key.
type Engine struct {
	masterKey []byte
}

// NewEngine creates a new encryption engine with the provided master key.
// The key must be exactly 32 bytes for AES-256. The key is copied, so the
// caller may wipe its own slice afterwards.
func NewEngine(key []byte) (*Engine, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	masterKey := make([]byte, KeySize)
	copy(masterKey, key)
	return &Engine{masterKey: masterKey}, nil
}

// Seal encrypts plaintext using envelope encryption.
// Returns: ciphertext (encrypted data), encryptedDEK (wrapped key), nonce, error.
func (engine *Engine) Seal(plaintext []byte) (ciphertext []byte, encryptedDEK []byte, nonce []byte, err error) {
	// Generate random Data Encryption Key
	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, nil, err
	}
	defer zeroBytes(dek) // Wipe DEK from memory when done

	// Generate random nonce. The same nonce is used under two different keys
	// (the fresh DEK and the master key); see docs/TECH_DEBT.md, TD-001.
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt plaintext with DEK
	dekCipher, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, err
	}
	// #nosec G407 -- nonce is filled from crypto/rand above, not hardcoded
	ciphertext = dekCipher.Seal(nil, nonce, plaintext, nil)

	// Wrap DEK with master key
	kekCipher, err := newGCM(engine.masterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	// #nosec G407 -- same random nonce, different key (TD-001)
	encryptedDEK = kekCipher.Seal(nil, nonce, dek, nil)

	return ciphertext, encryptedDEK, nonce, nil
}

// Open decrypts ciphertext using envelope encryption.
// Unwraps the DEK using the master key, then decrypts the ciphertext.
// Any modification of ciphertext, encryptedDEK or nonce makes Open fail.
func (engine *Engine) Open(ciphertext []byte, encryptedDEK []byte, nonce []byte) (plaintext []byte, err error) {
	// cipher.AEAD.Open panics on a nonce of the wrong length, so a corrupted
	// row must be rejected here instead of crashing the caller.
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("%w: nonce must be %d bytes, got %d", ErrMalformedEnvelope, NonceSize, len(nonce))
	}

	kekCipher, err := newGCM(engine.masterKey)
	if err != nil {
		return nil, err
	}

	// Decrypt DEK using the master key
	dek, err := kekCipher.Open(nil, nonce, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK: %w", err)
	}

	defer zeroBytes(dek) // Wipe dek from memory when done

	dekCipher, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	// Decrypt ciphertext with DEK
	plaintext, err = dekCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt content: %w", err)
	}

	return plaintext, nil
}

// Encrypt seals plaintext and returns it as a domain.Envelope.
// It lets *Engine satisfy the service.Encryptor interface.
func (engine *Engine) Encrypt(plaintext []byte) (*domain.Envelope, error) {
	ciphertext, encryptedDEK, nonce, err := engine.Seal(plaintext)
	if err != nil {
		return nil, err
	}
	return &domain.Envelope{
		Nonce:        nonce,
		EncryptedDEK: encryptedDEK,
		Ciphertext:   ciphertext,
	}, nil
}

// Decrypt opens a domain.Envelope produced by Encrypt.
func (engine *Engine) Decrypt(envelope *domain.Envelope) ([]byte, error) {
	if envelope == nil {
		return nil, ErrMalformedEnvelope
	}
	return engine.Open(envelope.Ciphertext, envelope.EncryptedDEK, envelope.Nonce)
}

// newGCM creates an AES-GCM cipher from the provided key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zeroBytes overwrites a byte slice with zeros.
// Used to clear sensitive key material from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
