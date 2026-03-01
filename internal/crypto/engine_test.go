package crypto

import (
	"bytes"
	"errors"
	"testing"
)

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

func TestEngine_RoundTrip(t *testing.T) {
	mockKey := make([]byte, 32)
	mockPlaintext := []byte("Forgive me, Father, for I have sinned")

	engine, err := NewEngine(mockKey)
	if err != nil {
		t.Errorf("Failed to create a new engine: %v", err)
	}

	mockCiphertext, mockEncryptedDEK, mockNonce, err := engine.Seal(mockPlaintext)
	if err != nil {
		t.Errorf("Engine failed to seal the message: %v", err)
	}

	mockDecryptedtext, err := engine.Open(mockCiphertext, mockEncryptedDEK, mockNonce)
	if err != nil {
		t.Errorf("Engine failed to open the cipher text: %v", err)
	}

	if !bytes.Equal(mockPlaintext, mockDecryptedtext) {
		t.Errorf("Falied the round trip expected %v, got %v", mockPlaintext, mockDecryptedtext)
	}
}

func TestEngine_Tamper(t *testing.T) {
	mockKey := make([]byte, 32)
	mockPlaintext := []byte("Forgive me, Father, for I have sinned")

	engine, err := NewEngine(mockKey)
	if err != nil {
		t.Errorf("Failed to create a new engine: %v", err)
	}

	mockCiphertext, mockEncryptedDEK, mockNonce, err := engine.Seal(mockPlaintext)
	if err != nil {
		t.Errorf("Engine failed to seal the message: %v", err)
	}

	mockCiphertext[0] ^= 0xff

	mockDecryptedtext, err := engine.Open(mockCiphertext, mockEncryptedDEK, mockNonce)
	if err == nil {
		t.Errorf("CRITICAL engine failed to authenticate. Expected err got %v", mockDecryptedtext)
	}
}
