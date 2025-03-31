package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"opsmanager/pkg/logger"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager manages JWT generation and verification
type JWTManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	log        *logger.Logger
}

// JWTConfig holds configuration for JWTManager
type JWTConfig struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Logger     *logger.Logger
}

// Claim keys used in JWT tokens
const (
	ClaimSubject   = "sub" // Subject claim (username)
	ClaimExpiresAt = "exp" // Expiration time claim
	ClaimIssuer    = "iss" // Issuer claim
)

// NewJWTManager initializes a new JWTManager with configuration
func NewJWTManager(cfg JWTConfig) (*JWTManager, error) {
	if cfg.PrivateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if err := cfg.PrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf("invalid private key: %v", err)
	}
	return &JWTManager{
		privateKey: cfg.PrivateKey,
		publicKey:  cfg.PrivateKey.Public().(*rsa.PublicKey),
		issuer:     cfg.Issuer,
		log:        cfg.Logger,
	}, nil
}

// GenerateToken generates a JWT token with custom expiration
func (m *JWTManager) GenerateToken(username string, expiration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		ClaimSubject:   username,
		ClaimExpiresAt: time.Now().Add(expiration).Unix(),
	}
	if m.issuer != "" {
		claims[ClaimIssuer] = m.issuer
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(m.privateKey)
	if err != nil && m.log != nil {
		m.log.Errorf("Failed to sign JWT for %s: %v", username, err)
	}
	return signedToken, err
}

// VerifyToken verifies a JWT token and returns its claims
func (m *JWTManager) VerifyToken(tokenString string) (jwt.MapClaims, error) {
	token, err := m.parseToken(tokenString)
	if err != nil {
		return nil, err
	}
	return m.validateClaims(token)
}

// GetUsernameFromToken extracts the username from a JWT token
func (m *JWTManager) GetUsernameFromToken(tokenString string) (string, error) {
	claims, err := m.VerifyToken(tokenString)
	if err != nil {
		return "", err
	}
	username, ok := claims[ClaimSubject].(string)
	if !ok {
		return "", errors.New("invalid token: missing or invalid subject")
	}
	return username, nil
}

// parseToken parses and verifies a JWT token using the public key
func (m *JWTManager) parseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	})
	if err != nil && m.log != nil {
		m.log.Warnf("JWT parsing failed: %v", err)
	}
	return token, err
}

// validateClaims checks token validity and returns claims
func (m *JWTManager) validateClaims(token *jwt.Token) (jwt.MapClaims, error) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if m.issuer != "" {
			if iss, ok := claims[ClaimIssuer].(string); !ok || iss != m.issuer {
				return nil, errors.New("invalid token: issuer mismatch")
			}
		}
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
