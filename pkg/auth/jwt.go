package auth

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager handles JWT generation and verification
type JWTManager struct {
	privateKey *rsa.PrivateKey // RSA private key for signing tokens
}

// Claim keys used in JWT tokens
const (
	claimSubject   = "sub" // Subject claim (username)
	claimExpiresAt = "exp" // Expiration time claim
)

// NewJWTManager creates a new JWTManager instance
func NewJWTManager(privateKey *rsa.PrivateKey) (*JWTManager, error) {
	// Ensure private key is provided
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	return &JWTManager{privateKey: privateKey}, nil
}

// GenerateToken generates a JWT token with custom expiration
func (m *JWTManager) GenerateToken(username string, expiration time.Duration) (string, error) {
	// Create claims with username and expiration
	claims := jwt.MapClaims{
		claimSubject:   username,
		claimExpiresAt: time.Now().Add(expiration).Unix(),
	}

	// Create token with RS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign token using the private key
	return token.SignedString(m.privateKey)
}

// VerifyToken verifies a JWT token and returns its claims if valid
func (m *JWTManager) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	// Parse and verify the token
	token, err := m.parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Verify token validity and extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// GetUsernameFromToken extracts the username from a JWT token
func (m *JWTManager) GetUsernameFromToken(tokenString string) (string, error) {
	// Parse and verify the token
	token, err := m.parseToken(tokenString)
	if err != nil {
		return "", err
	}

	// Verify token validity and extract username from claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if sub, ok := claims[claimSubject].(string); ok {
			return sub, nil
		}
		return "", fmt.Errorf("invalid token: missing or invalid subject")
	}
	return "", fmt.Errorf("invalid token")
}

// parseToken parses and verifies a JWT token with the RSA public key
func (m *JWTManager) parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Provide public key for verification
		return m.privateKey.Public(), nil
	})
}
