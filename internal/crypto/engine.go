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
func (e *Engine) Seal(plaintext []byte) (ciphertext, encryptedDEK, nonce []byte, err error) {
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
	dataGCM, err := newGCM(dek)
	if err != nil {
		return nil, nil, nil, err
	}
	ciphertext = dataGCM.Seal(nil, nonce, plaintext, nil)

	// Wrap DEK with master key
	masterGCM, err := newGCM(e.masterKey)
	if err != nil {
		return nil, nil, nil, err
	}
	encryptedDEK = masterGCM.Seal(nil, nonce, dek, nil)

	return ciphertext, encryptedDEK, nonce, nil
}

// Open decrypts ciphertext using envelope encryption.
// Unwraps the DEK using the master key, then decrypts the ciphertext.
func (e *Engine) Open(ciphertext, encryptedDEK, nonce []byte) (plaintext []byte, err error) {
	// TODO(human): Implement decryption
	// 1. Unwrap DEK: decrypt encryptedDEK with masterKey using newGCM + Open
	// 2. Decrypt: use DEK to decrypt ciphertext
	// 3. Zero the DEK from memory with defer zeroBytes(dek)
	// 4. Return plaintext
	return nil, errors.New("not implemented")
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
