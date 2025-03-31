package rsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"opsmanager/pkg/crypto"
	"opsmanager/pkg/etcd"
)

// KeyManager manages RSA key generation and storage.
type KeyManager struct {
	privateKey *rsa.PrivateKey // RSA private key
	encrypted  []byte          // Encrypted key bytes (for debugging or reuse)
}

// RSA configuration constants.
const (
	keySize     = 2048              // Size of the RSA key in bits
	keyEtcdPath = "rsa_private_key" // Etcd path for the encrypted RSA key
)

// NewKeyManager initializes a KeyManager with an RSA key from etcd or generates a new one.
func NewKeyManager(ctx context.Context, logger *log.Logger, etcdClient *etcd.Client, aesKey []byte) (*KeyManager, error) {
	if len(aesKey) == 0 {
		return nil, fmt.Errorf("AES key cannot be empty")
	}

	logger.Printf("Checking for RSA key in etcd at %s", keyEtcdPath)
	encryptedKey, err := etcdClient.GetSession(ctx, keyEtcdPath)
	if err != nil {
		logger.Printf("Failed to retrieve RSA key from etcd: %v", err)
		return nil, fmt.Errorf("failed to get RSA key from etcd: %w", err)
	}

	if encryptedKey == "" {
		return generateNewKey(ctx, logger, etcdClient, aesKey)
	}
	return loadExistingKey(logger, aesKey, encryptedKey)
}

// generateNewKey creates and stores a new RSA private key.
func generateNewKey(ctx context.Context, logger *log.Logger, etcdClient *etcd.Client, aesKey []byte) (*KeyManager, error) {
	logger.Printf("Generating new %d-bit RSA key", keySize)

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		logger.Printf("Failed to generate %d-bit RSA key: %v", keySize, err)
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Encrypt with AES
	encryptedKey, err := crypto.EncryptAES(aesKey, privateKeyPEM)
	if err != nil {
		logger.Printf("Failed to encrypt RSA key: %v", err)
		return nil, fmt.Errorf("failed to encrypt RSA key: %w", err)
	}

	// Store in etcd (persistent)
	if err := etcdClient.StoreSession(ctx, keyEtcdPath, string(encryptedKey)); err != nil {
		logger.Printf("Failed to store RSA key in etcd at %s: %v", keyEtcdPath, err)
		return nil, fmt.Errorf("failed to store RSA key in etcd: %w", err)
	}

	logger.Printf("Generated and stored %d-bit RSA key successfully", keySize)
	return &KeyManager{
		privateKey: privateKey,
		encrypted:  encryptedKey,
	}, nil
}

// loadExistingKey decrypts and loads an RSA private key from etcd.
func loadExistingKey(logger *log.Logger, aesKey []byte, encryptedKey string) (*KeyManager, error) {
	// Decrypt the key
	decryptedPEM, err := crypto.DecryptAES(aesKey, []byte(encryptedKey))
	if err != nil {
		logger.Printf("Failed to decrypt RSA key: %v", err)
		return nil, fmt.Errorf("failed to decrypt RSA key: %w", err)
	}

	// Decode PEM
	block, rest := pem.Decode(decryptedPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		logger.Printf("Invalid PEM format or type for RSA key")
		return nil, fmt.Errorf("invalid PEM format or type")
	}
	if len(rest) > 0 {
		logger.Printf("Ignoring extra data after PEM block (%d bytes)", len(rest))
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.Printf("Failed to parse RSA key: %v", err)
		return nil, fmt.Errorf("failed to parse RSA key: %w", err)
	}

	logger.Printf("Loaded RSA key successfully from etcd")
	return &KeyManager{
		privateKey: privateKey,
		encrypted:  []byte(encryptedKey),
	}, nil
}

// PrivateKey returns the managed RSA private key.
func (km *KeyManager) PrivateKey() *rsa.PrivateKey {
	return km.privateKey
}
