package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt_Success(t *testing.T) {
	key := [32]byte{}
	copy(key[:], []byte("my_secure_test_key_123456789012"))

	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("Hello ZTP encryption!")
	encrypted, err := Encrypt(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(key, nonce, encrypted, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch. Expected: %s, Got: %s", plaintext, decrypted)
	}
}

func TestDecrypt_Failure(t *testing.T) {
	key := [32]byte{}
	copy(key[:], []byte("my_secure_test_key_123456789012"))
	badKey := [32]byte{}
	copy(badKey[:], []byte("wrong_key_should_fail_test!!!"))

	nonce, _ := GenerateNonce()
	message := []byte("ZTP Message")

	encrypted, _ := Encrypt(key, nonce, message, nil)
	_, err := Decrypt(badKey, nonce, encrypted, nil)
	if err == nil {
		t.Error("Expected decryption failure with wrong key, got nil error")
	}
}
