package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Key and nonce size constants for AES-256-GCM
const (
	KeySize   = 32 // AES-256 requires 32-byte keys
	NonceSize = 12 // GCM standard nonce size (96 bits)
)

var (
	ErrInvalidKeySize = errors.New("master key must be exactly 32 bytes (AES-256)")
)

// Engine provides envelope encryption using AES-256-GCM.
// Each Seal operation generates a unique Data Encryption Key (DEK),
// encrypts the plaintext with the DEK, then wraps the DEK with the master key.
type Engine struct {
	masterKey []byte
}

// NewEngine creates a new encryption engine with the provided master key.
// The key must be exactly 32 bytes for AES-256.
func NewEngine(key []byte) (*Engine, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return &Engine{masterKey: key}, nil
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

	// Generate random nonce
	nonce = make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt plaintext with DEK
	dekCipher, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, err
	}
	ciphertext = dekCipher.Seal(nil, nonce, plaintext, nil)

	// Wrap DEK with master key
	kekCipher, err := newGCM(engine.masterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	encryptedDEK = kekCipher.Seal(nil, nonce, dek, nil)

	return ciphertext, encryptedDEK, nonce, nil
}

// Open decrypts ciphertext using envelope encryption.
// Unwraps the DEK using the master key, then decrypts the ciphertext.
func (engine *Engine) Open(ciphertext []byte, encryptedDEK []byte, nonce []byte) (plaintext []byte, err error) {

	kekCipher, err := newGCM(engine.masterKey)
	if err != nil {
		return nil, err
	}

	// Decrypt DEK using the master key
	dek, err := kekCipher.Open(nil, nonce, encryptedDEK, nil)
	if err != nil {
		return nil, err
	}

	defer zeroBytes(dek) // Wipe dek from memory when done

	dekCipher, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	// Decrypt ciphertext with DEK
	plaintext, err = dekCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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
