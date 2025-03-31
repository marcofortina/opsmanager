package rsa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"opsmanager/pkg/crypto"
	"opsmanager/pkg/etcd"
	"opsmanager/pkg/logger"
)

// KeyManager manages RSA key generation and storage
type KeyManager struct {
	privateKey *rsa.PrivateKey
	encrypted  []byte
	log        *logger.Logger
	etcd       *etcd.Client
	aesMgr     *crypto.AESManager
	keyPath    string
	keySize    int
}

// KeyManagerConfig holds configuration for KeyManager
type KeyManagerConfig struct {
	KeySize    int
	KeyPath    string
	AESKey     []byte
	EtcdClient *etcd.Client
	Logger     *logger.Logger
}

// Default RSA constants
const (
	DefaultKeySize   = 2048              // Default RSA key size in bits
	DefaultKeyPath   = "rsa_private_key" // Default etcd path for encrypted key
	DefaultOpTimeout = 2 * time.Second   // Default timeout for etcd operations
)

// NewKeyManager initializes a KeyManager with an RSA key from etcd or generates a new one
func NewKeyManager(cfg KeyManagerConfig) (*KeyManager, error) {
	if cfg.KeySize < 2048 {
		cfg.KeySize = DefaultKeySize
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = DefaultKeyPath
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}

	aesMgr, err := crypto.NewAESManager(cfg.AESKey, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES manager: %v", err)
	}

	km := &KeyManager{
		log:     cfg.Logger,
		etcd:    cfg.EtcdClient,
		aesMgr:  aesMgr,
		keyPath: cfg.KeyPath,
		keySize: cfg.KeySize,
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultOpTimeout)
	defer cancel()

	encryptedKey, err := cfg.EtcdClient.GetSession(ctx, cfg.KeyPath)
	if err != nil {
		km.log.Errorf("Failed to retrieve RSA key from etcd: %v", err)
		return nil, fmt.Errorf("failed to get RSA key: %v", err)
	}

	if encryptedKey == "" {
		return km.generateNewKey(ctx)
	}
	return km.loadExistingKey(encryptedKey)
}

// generateNewKey creates and stores a new RSA private key
func (km *KeyManager) generateNewKey(ctx context.Context) (*KeyManager, error) {
	km.log.Infof("Generating new %d-bit RSA key", km.keySize)

	privateKey, err := rsa.GenerateKey(rand.Reader, km.keySize)
	if err != nil {
		km.log.Errorf("Failed to generate RSA key: %v", err)
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	encryptedKey, err := km.aesMgr.EncryptAES(privateKeyPEM)
	if err != nil {
		km.log.Errorf("Failed to encrypt RSA key: %v", err)
		return nil, fmt.Errorf("failed to encrypt RSA key: %v", err)
	}

	if err := km.etcd.StoreSession(ctx, km.keyPath, string(encryptedKey)); err != nil {
		km.log.Errorf("Failed to store RSA key at %s: %v", km.keyPath, err)
		return nil, fmt.Errorf("failed to store RSA key: %v", err)
	}

	km.privateKey = privateKey
	km.encrypted = encryptedKey
	km.log.Infof("Generated and stored %d-bit RSA key", km.keySize)
	return km, nil
}

// loadExistingKey decrypts and loads an RSA private key
func (km *KeyManager) loadExistingKey(encryptedKey string) (*KeyManager, error) {
	decryptedPEM, err := km.aesMgr.DecryptAES([]byte(encryptedKey))
	if err != nil {
		km.log.Errorf("Failed to decrypt RSA key: %v", err)
		return nil, fmt.Errorf("failed to decrypt RSA key: %v", err)
	}

	block, rest := pem.Decode(decryptedPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		km.log.Errorf("Invalid PEM format or type for RSA key")
		return nil, fmt.Errorf("invalid PEM format or type")
	}
	if len(rest) > 0 {
		km.log.Warnf("Extra data after PEM block: %d bytes", len(rest))
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		km.log.Errorf("Failed to parse RSA key: %v", err)
		return nil, fmt.Errorf("failed to parse RSA key: %v", err)
	}

	km.privateKey = privateKey
	km.encrypted = []byte(encryptedKey)
	km.log.Infof("Loaded RSA key from etcd")
	return km, nil
}

// PrivateKey returns the RSA private key
func (km *KeyManager) PrivateKey() *rsa.PrivateKey {
	return km.privateKey
}

// RefreshKey regenerates and stores a new RSA key
func (km *KeyManager) RefreshKey(ctx context.Context) error {
	newKM, err := km.generateNewKey(ctx)
	if err != nil {
		return err
	}
	km.privateKey = newKM.privateKey
	km.encrypted = newKM.encrypted
	return nil
}
