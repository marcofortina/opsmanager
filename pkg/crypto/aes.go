package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"opsmanager/pkg/logger"
)

// AESManager manages AES-GCM encryption and decryption
type AESManager struct {
	key   []byte
	block cipher.Block
	gcm   cipher.AEAD
	log   *logger.LogManager
}

// NewAESManager initializes a new AESManager with a key
func NewAESManager(key []byte, log *logger.LogManager) (*AESManager, error) {
	// Validate key length (AES-128, AES-192, or AES-256)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid AES key length: got %d, expected 16, 24, or 32", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode: %v", err)
	}

	return &AESManager{
		key:   key,
		block: block,
		gcm:   gcm,
		log:   log,
	}, nil
}

// EncryptAES encrypts data using AES-GCM
func (m *AESManager) EncryptAES(plaintext []byte) ([]byte, error) {
	nonceSize := m.gcm.NonceSize()
	nonce := make([]byte, nonceSize)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		if m.log != nil {
			m.log.Errorf("Failed to generate nonce: %v", err)
		}
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := m.gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES decrypts AES-GCM encrypted data
func (m *AESManager) DecryptAES(ciphertext []byte) ([]byte, error) {
	nonceSize := m.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short to contain nonce")
	}

	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := m.gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		if m.log != nil {
			m.log.Errorf("Failed to decrypt AES-GCM data: %v", err)
		}
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}
	return plaintext, nil
}
