type Encryptor interface {
	Encrypt(ciphertext []byte, encryptedDEK []byte, nonce []byte, err error) []byte, []byte, []byte, error
	Decrypt()
}
