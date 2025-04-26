package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var sharedSecret = []byte("supersecretkey123") // 🔐 Should be stored securely (env/config)

// TokenClaims represents the identity claims encoded in a token
type TokenClaims struct {
	ClientID string    `json:"client_id"`
	Role     string    `json:"role"` // ⭐ NEW field for dynamic roles
	Expires  time.Time `json:"expires"`
}

// CreateToken generates a signed token for a client
func CreateToken(clientID string, role string, duration time.Duration) (string, error) {
	claims := TokenClaims{
		ClientID: clientID,
		Role:     role,
		Expires:  time.Now().Add(duration),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	sig := hmac.New(sha256.New, sharedSecret)
	sig.Write(payload)
	signature := sig.Sum(nil)

	token := base64.StdEncoding.EncodeToString(payload) + "." + base64.StdEncoding.EncodeToString(signature)
	return token, nil
}

// VerifyToken checks the token signature and expiration
func VerifyToken(token string) (*TokenClaims, error) {
	parts := splitToken(token)
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	payload, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}
	signature, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	expectedSig := hmac.New(sha256.New, sharedSecret)
	expectedSig.Write(payload)
	if !hmac.Equal(signature, expectedSig.Sum(nil)) {
		return nil, errors.New("signature verification failed")
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if time.Now().After(claims.Expires) {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

// splitToken separates the payload and signature
func splitToken(token string) []string {
	parts := make([]string, 0, 2)
	for i, c := range token {
		if c == '.' {
			parts = append(parts, token[:i], token[i+1:])
			break
		}
	}
	return parts
}
