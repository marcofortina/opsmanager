package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// main generates a random AES-256 key
func main() {
	// Create a 32-byte slice for AES-256 key
	key := make([]byte, 32)

	// Fill slice with random bytes
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	// Encode key to hexadecimal format
	hexKey := hex.EncodeToString(key)

	// Print hex-encoded key for config.yaml
	fmt.Println("Hex (for config.yaml):", hexKey)
}
