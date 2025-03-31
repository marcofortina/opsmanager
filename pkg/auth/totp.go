package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"time"
)

// TOTP configuration constants
const (
	totpInterval    = 30      // Time step in seconds (standard TOTP interval)
	totpCodeLength  = 6       // Length of the TOTP code (6 digits)
	totpCodeModulus = 1000000 // Modulus for generating a 6-digit code (10^6)
)

// GenerateTOTP generates a TOTP code based on a seed and time
func GenerateTOTP(seed string, t time.Time) (string, error) {
	// Decode base32 seed into bytes
	secret, err := base32.StdEncoding.DecodeString(seed)
	if err != nil {
		return "", fmt.Errorf("failed to decode base32 seed: %v", err)
	}

	// Calculate counter from time (number of 30-second intervals)
	counter := uint64(math.Floor(float64(t.Unix()) / totpInterval))

	// Convert counter to 8-byte message (big-endian)
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter & 0xff)
		counter >>= 8
	}

	// Compute HMAC-SHA1 hash with secret and message
	h := hmac.New(sha1.New, secret)
	h.Write(msg)
	hash := h.Sum(nil)

	// Extract dynamic offset from the last byte of the hash
	offset := hash[len(hash)-1] & 0xf

	// Extract 4 bytes starting at offset and compute 6-digit code
	value := (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1])<<16 |
		int(hash[offset+2])<<8 |
		int(hash[offset+3])) % totpCodeModulus

	// Format the code as a 6-digit string with leading zeros
	return fmt.Sprintf("%0*d", totpCodeLength, value), nil
}

// VerifyTOTP checks if a provided TOTP code is valid for the current time
func VerifyTOTP(seed, code string) bool {
	// Generate expected TOTP code for the current time
	expected, err := GenerateTOTP(seed, time.Now())
	if err != nil {
		return false
	}

	// Compare provided code with expected code
	return code == expected
}
