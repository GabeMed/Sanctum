type Envelope struct {
	nonce        []byte
	encryptedDEK []byte
	ciphertext   []byte
}

type Reflection struct {
	id           uuid
	day          time.time
	nonce        []byte
	encryptedDEK []byte
	ciphertext   []byte
	created_at   time
}

type ReflectionOutput struct {
	id         uuid
	day        time.time
	plaintext  string
	created_at time
}
