package auth

import (
	"crypto/rand"
	"encoding/base64"

	"opsmanager/pkg/logger"
)

// CSRFManager manages CSRF token generation
type CSRFManager struct {
	tokenLength int
	log         *logger.LogManager
}

// CSRFTokenLength is the default length for CSRF tokens
const CSRFTokenLength = 32

// NewCSRFManager initializes a new CSRFManager
func NewCSRFManager(tokenLength int, log *logger.LogManager) *CSRFManager {
	if tokenLength <= 0 {
		tokenLength = CSRFTokenLength
	}
	if log == nil {
		log = logger.Default()
	}
	return &CSRFManager{
		tokenLength: tokenLength,
		log:         log,
	}
}

// GenerateToken generates a secure random CSRF token
func (m *CSRFManager) GenerateToken() (string, error) {
	b := make([]byte, m.tokenLength)

	_, err := rand.Read(b)
	if err != nil {
		if m.log != nil {
			m.log.Errorf("Failed to generate CSRF token: %v", err)
		}
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(b)
	return token, nil
}
