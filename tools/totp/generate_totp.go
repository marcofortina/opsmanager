package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"math"
	"time"
)

// GenerateTOTP generates a TOTP code based on a seed and time
func GenerateTOTP(seed string, t time.Time) (string, error) {
	// Decode base32 seed to bytes
	secret, err := base32.StdEncoding.DecodeString(seed)
	if err != nil {
		return "", err
	}

	// Calculate counter based on time (30-second intervals)
	counter := uint64(math.Floor(float64(t.Unix()) / 30))

	// Convert counter to 8-byte message
	msg := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		msg[i] = byte(counter)
		counter >>= 8
	}

	// Create HMAC-SHA1 hash using secret and message
	h := hmac.New(sha1.New, secret)
	h.Write(msg)
	hash := h.Sum(nil)

	// Determine offset from last byte of hash
	offset := hash[len(hash)-1] & 0xf

	// Extract 4 bytes starting at offset and compute 6-digit code
	value := (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1])<<16 |
		int(hash[offset+2])<<8 |
		int(hash[offset+3])) % 1000000

	// Format code as 6-digit string
	return fmt.Sprintf("%06d", value), nil
}

func main() {
	// Define TOTP seed (replace with your own)
	seed := "JBSWY3DPEHPK3PXP"

	// Generate current TOTP code
	code, err := GenerateTOTP(seed, time.Now())
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Print the current TOTP code
	fmt.Printf("Current TOTP code: %s\n", code)
}
