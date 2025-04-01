package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"time"

	"opsmanager/pkg/etcd"
	"opsmanager/pkg/logger"
)

// TOTPManager manages TOTP code generation and verification
type TOTPManager struct {
	secret     []byte
	interval   int
	codeLength int
	log        *logger.LogManager
	etcd       *etcd.Client
}

// TOTPConfig holds configuration for TOTPManager
type TOTPConfig struct {
	Seed       string
	Interval   int // Time step in seconds
	CodeLength int // Length of the TOTP code
	Logger     *logger.LogManager
	Etcd       *etcd.Client
}

// Default TOTP constants
const (
	DefaultTOTPInterval   = 30      // Default time step in seconds
	DefaultTOTPCodeLength = 6       // Default length of TOTP code
	totpCodeModulus       = 1000000 // Modulus for 6-digit code (10^6)
)

// NewTOTPManager initializes a new TOTPManager
func NewTOTPManager(cfg *TOTPConfig) (*TOTPManager, error) {
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultTOTPInterval
	}
	if cfg.CodeLength <= 0 {
		cfg.CodeLength = DefaultTOTPCodeLength
	}
	if cfg.Etcd == nil {
		return nil, fmt.Errorf("etcd client is required")
	}

	var secret []byte
	if cfg.Seed == "" {
		secret = nil
	} else {
		var err error
		secret, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cfg.Seed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode TOTP seed: %v", err)
		}
		if len(secret) < 10 {
			return nil, fmt.Errorf("TOTP seed too short")
		}
	}

	return &TOTPManager{
		secret:     secret,
		interval:   cfg.Interval,
		codeLength: cfg.CodeLength,
		log:        cfg.Logger,
		etcd:       cfg.Etcd,
	}, nil
}

// GenerateTOTP generates a TOTP code for a given time
func (m *TOTPManager) GenerateTOTP(t *time.Time) (string, error) {
	if m.secret == nil {
		return "", fmt.Errorf("no TOTP secret set")
	}
	m.log.Debugf("Using secret for TOTP generation: %x", m.secret)

	// Calculate counter based on time
	counter := uint64(math.Floor(float64(t.Unix()) / float64(m.interval)))
	m.log.Debugf("TOTP counter: %d", counter)

	// Convert counter to 8-byte array (big-endian)
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter & 0xff)
		counter >>= 8
	}
	m.log.Debugf("Counter bytes: %x", msg)

	// Compute HMAC-SHA1
	h := hmac.New(sha1.New, m.secret)
	h.Write(msg)
	hash := h.Sum(nil)
	m.log.Debugf("HMAC-SHA1 hash: %x", hash)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0xf
	m.log.Debugf("Offset: %d", offset)

	// Extract 4 bytes and compute value
	value := (int(hash[offset]&0x7f) << 24) |
		(int(hash[offset+1]) << 16) |
		(int(hash[offset+2]) << 8) |
		(int(hash[offset+3]))
	m.log.Debugf("Raw value: %d", value)

	// Apply modulus to get final code
	value = value % totpCodeModulus
	m.log.Debugf("Value after modulus: %d", value)

	// Format as string with leading zeros
	return fmt.Sprintf("%0*d", m.codeLength, value), nil
}

// VerifyTOTP verifies a TOTP code with a time window
func (m *TOTPManager) VerifyTOTP(code string, t time.Time) bool {
	if m.secret == nil {
		m.log.Errorf("No TOTP secret set for verification")
		return false
	}
	for i := -1; i <= 1; i++ {
		checkTime := t.Add(time.Duration(i*m.interval) * time.Second)
		expected, err := m.GenerateTOTP(&checkTime)
		if err != nil {
			m.log.Errorf("Failed to generate TOTP for verification: %v", err)
			return false
		}
		m.log.Debugf("Generated TOTP code for time %s: %s (expected: %s)", checkTime.Format(time.RFC3339), expected, code)
		if code == expected {
			return true
		}
	}
	m.log.Warn("TOTP verification failed")
	return false
}

// GetOrCreateTOTPSecret retrieves or generates a TOTP secret for a user
func (m *TOTPManager) GetOrCreateTOTPSecret(ctx context.Context, username string) (string, error) {
	secretKey := "totp_secret:" + username
	existingSecret, err := m.etcd.GetSession(ctx, secretKey)
	if err != nil {
		m.log.Errorf("Failed to retrieve TOTP secret for %s: %v", username, err)
		return "", fmt.Errorf("failed to retrieve TOTP secret: %v", err)
	}
	if existingSecret != "" {
		// Decode the base32 secret
		decodedSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(existingSecret)
		if err != nil {
			return "", fmt.Errorf("failed to decode existing TOTP secret for %s: %v", username, err)
		}
		m.secret = decodedSecret
		m.log.Debugf("Retrieved and decoded TOTP secret for %s: %s (decoded: %x)", username, existingSecret, decodedSecret)
		return existingSecret, nil
	}

	newSecret := generateRandomBase32Secret(20)
	// Decode the new secret to store it in m.secret
	decodedSecret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(newSecret)
	if err != nil {
		return "", fmt.Errorf("failed to decode new TOTP secret for %s: %v", username, err)
	}
	if err := m.etcd.StoreSession(ctx, secretKey, newSecret); err != nil {
		m.log.Errorf("Failed to store TOTP secret for %s: %v", username, err)
		return "", fmt.Errorf("failed to store TOTP secret: %v", err)
	}
	m.secret = decodedSecret
	m.log.Debugf("Generated and decoded new TOTP secret for %s: %s (decoded: %x)", username, newSecret, decodedSecret)
	return newSecret, nil
}

// IsSetupCompleted checks if 2FA setup is completed for a user
func (m *TOTPManager) IsSetupCompleted(ctx context.Context, username string) (bool, error) {
	setupKey := "totp_setup_completed:" + username
	value, err := m.etcd.GetSession(ctx, setupKey)
	if err != nil {
		m.log.Errorf("Failed to check 2FA setup status for %s: %v", username, err)
		return false, fmt.Errorf("failed to check 2FA setup status: %v", err)
	}
	if value == "" {
		m.log.Debugf("2FA setup not completed for %s", username)
		return false, nil
	}
	m.log.Debugf("2FA setup completed for %s: %s", username, value)
	return value == "true", nil
}

// MarkSetupCompleted marks 2FA setup as completed for a user
func (m *TOTPManager) MarkSetupCompleted(ctx context.Context, username string) error {
	setupKey := "totp_setup_completed:" + username
	if err := m.etcd.StoreSession(ctx, setupKey, "true"); err != nil {
		m.log.Errorf("Failed to store 2FA setup status for %s: %v", username, err)
		return err
	}
	m.log.Debugf("Marked 2FA setup as completed for %s", username)
	return nil
}

// GetQRCodeURL generates a QR code URL for a user
func (m *TOTPManager) GetQRCodeURL(username, secret string) string {
	return fmt.Sprintf("otpauth://totp/OpsManager:%s?secret=%s&issuer=OpsManager", username, secret)
}

// generateRandomBase32Secret generates a random base32-encoded secret
func generateRandomBase32Secret(length int) string {
	randBytes := make([]byte, length)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random secret: %v", err))
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randBytes)
}
