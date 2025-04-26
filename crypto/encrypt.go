package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSize = 12
	KeySize   = 32
)

func Encrypt(key [KeySize]byte, nonce [NonceSize]byte, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, additionalData), nil
}

func Decrypt(key [KeySize]byte, nonce [NonceSize]byte, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce[:], ciphertext, additionalData)
}

func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}
