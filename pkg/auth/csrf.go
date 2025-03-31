package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"opsmanager/pkg/logger"
)

// CSRFManager manages CSRF token generation
type CSRFManager struct {
	tokenLength int
	log         *logger.Logger
	bufferPool  *sync.Pool
}

// CSRFTokenLength is the default length for CSRF tokens
const CSRFTokenLength = 32

// NewCSRFManager initializes a new CSRFManager
func NewCSRFManager(tokenLength int, log *logger.Logger) *CSRFManager {
	if tokenLength <= 0 {
		tokenLength = CSRFTokenLength
	}
	if log == nil {
		log = logger.Default()
	}
	return &CSRFManager{
		tokenLength: tokenLength,
		log:         log,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, tokenLength)
				return &b // Restituisce *[]byte
			},
		},
	}
}

// GenerateToken generates a secure random CSRF token
func (m *CSRFManager) GenerateToken() (string, error) {
	bPtr := m.bufferPool.Get().(*[]byte) // Corretto: attende *[]byte
	defer m.bufferPool.Put(bPtr)
	b := *bPtr // Dereferenzia per usare il []byte

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
