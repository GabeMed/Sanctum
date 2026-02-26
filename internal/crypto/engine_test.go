import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type Engine struct {
	masterKey []byte
}

func NewEngine(key []byte) (*Engine, error) {
	if len(key) != 32 {
		return nil, errors.New("master key must be exact 32 bytes (AES-256)")
	}
}

func (engine *Engine) Seal(plaintext []byte) (ciphertext []byte, encryptedDEK []byte, nonce []byte, err error) {
	// 1. Generate random 32-byte DEK
	// 2. Generate random 12-byte Nonce
	// 3. Encrypt plaintext with DEK (AES-GCM)
	// 4. Encrypt DEK with masterKey (AES-GCM)
	// 5. Return the pieces
}

func (e *Engine) Open(ciphertext, encryptedDEK, nonce []byte) (plaintext []byte, err error) {
	// 1. Decrypt encryptedDEK with masterKey (AES-GCM)
	// 2. Decrypt ciphertext with the unencrypted DEK (AES-GCM)
	// 3. Return plaintext
}
