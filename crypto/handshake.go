package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 32
	SharedKeySize  = 32
)

// KeyPair holds a Curve25519 key pair
type KeyPair struct {
	Private [PrivateKeySize]byte
	Public  [PublicKeySize]byte
}

// GenerateKeyPair creates a new x25519 keypair
func GenerateKeyPair() (*KeyPair, error) {
	var priv [PrivateKeySize]byte
	_, err := rand.Read(priv[:])
	if err != nil {
		return nil, err
	}

	// Clamp private key for x25519
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [PublicKeySize]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return &KeyPair{Private: priv, Public: pub}, nil
}

// ComputeSharedKey performs ECDH to generate a shared secret
func ComputeSharedKey(privKey, peerPubKey [32]byte) ([SharedKeySize]byte, error) {
	sharedOut, err := curve25519.X25519(privKey[:], peerPubKey[:])
	if err != nil {
		return [SharedKeySize]byte{}, err
	}

	var shared [SharedKeySize]byte
	copy(shared[:], sharedOut)
	return shared, nil
}

// DeriveSessionKey derives a session key from the shared secret
func DeriveSessionKey(sharedSecret [32]byte, contextInfo []byte) [32]byte {
	h := sha256.New()
	h.Write(sharedSecret[:])
	h.Write(contextInfo)
	var sessionKey [32]byte
	copy(sessionKey[:], h.Sum(nil))
	return sessionKey
}

// EncodePublicKey serializes a public key
func EncodePublicKey(pub [32]byte) []byte {
	return pub[:]
}

// DecodePublicKey parses a serialized public key
func DecodePublicKey(data []byte) ([32]byte, error) {
	if len(data) != PublicKeySize {
		return [32]byte{}, errors.New("invalid public key size")
	}
	var key [32]byte
	copy(key[:], data)
	return key, nil
}
