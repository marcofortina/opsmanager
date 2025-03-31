package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"sync"
	"time"

	"opsmanager/pkg/logger"
)

// TOTPManager manages TOTP code generation and verification
type TOTPManager struct {
	secret     []byte
	interval   int
	codeLength int
	log        *logger.Logger
	pool       *sync.Pool
}

// TOTPConfig holds configuration for TOTPManager
type TOTPConfig struct {
	Seed       string
	Interval   int // Time step in seconds
	CodeLength int // Length of the TOTP code
	Logger     *logger.Logger
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

	if cfg.Seed == "" {
		return nil, fmt.Errorf("TOTP seed cannot be empty")
	}

	secret, err := base32.StdEncoding.DecodeString(cfg.Seed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode TOTP seed: %v", err)
	}
	if len(secret) < 10 { // Minimum entropy
		return nil, fmt.Errorf("TOTP seed too short")
	}

	return &TOTPManager{
		secret:     secret,
		interval:   cfg.Interval,
		codeLength: cfg.CodeLength,
		log:        cfg.Logger,
		pool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, 8)
				return &b // Returns *[]byte
			},
		},
	}, nil
}

// GenerateTOTP generates a TOTP code for a given time
func (m *TOTPManager) GenerateTOTP(t *time.Time) (string, error) {
	counter := uint64(math.Floor(float64(t.Unix()) / float64(m.interval)))
	msgPtr := m.pool.Get().(*[]byte) // Correct: expects *[]byte
	defer m.pool.Put(msgPtr)
	msg := *msgPtr // Dereference to get []byte

	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter & 0xff)
		counter >>= 8
	}

	h := hmac.New(sha1.New, m.secret)
	h.Write(msg)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0xf
	value := (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1])<<16 |
		int(hash[offset+2])<<8 |
		int(hash[offset+3])) % totpCodeModulus

	return fmt.Sprintf("%0*d", m.codeLength, value), nil
}

// VerifyTOTP verifies a TOTP code with a time window
func (m *TOTPManager) VerifyTOTP(code string, t time.Time) bool {
	for i := -1; i <= 1; i++ { // Window of ±1 interval
		checkTime := t.Add(time.Duration(i*m.interval) * time.Second)
		expected, err := m.GenerateTOTP(&checkTime)
		if err != nil {
			if m.log != nil {
				m.log.Errorf("Failed to generate TOTP for verification: %v", err)
			}
			return false
		}
		if code == expected {
			return true
		}
	}
	if m.log != nil {
		m.log.Warn("TOTP verification failed")
	}
	return false
}
