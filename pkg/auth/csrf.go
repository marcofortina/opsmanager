package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// CSRFManager handles CSRF token generation
type CSRFManager struct{}

// TokenLength defines the size of the CSRF token in bytes
const TokenLength = 32 // 32 bytes = 256 bits of randomness

// NewCSRFManager creates a new CSRFManager instance
func NewCSRFManager() *CSRFManager {
	return &CSRFManager{}
}

// GenerateToken generates a secure random CSRF token
func (m *CSRFManager) GenerateToken() (string, error) {
	// Allocate buffer for random bytes
	b := make([]byte, TokenLength)

	// Fill buffer with cryptographically secure random data
	_, err := rand.Read(b)
	if err != nil {
		return "", err // Return empty string and error if random generation fails
	}

	// Encode the random bytes to a URL-safe base64 string
	token := base64.URLEncoding.EncodeToString(b)
	return token, nil
}
