package auth

import "log"

// LoginManager handles user authentication
type LoginManager struct {
	logger *log.Logger // Logger for authentication events
}

// Hardcoded credentials (temporary)
const (
	defaultUsername = "admin"     // Default username for authentication
	defaultPassword = "secret123" // Default password for authentication
)

// NewLoginManager creates a new LoginManager instance
func NewLoginManager(logger *log.Logger) *LoginManager {
	return &LoginManager{logger: logger}
}

// VerifyCredentials checks if the provided username and password are valid
func (m *LoginManager) VerifyCredentials(username, password string) bool {
	// Compare provided credentials with hardcoded values
	if username == defaultUsername && password == defaultPassword {
		m.logger.Printf("Credentials verified successfully for user '%s'", username)
		return true
	}

	// Log failed authentication attempt
	m.logger.Printf("Invalid credentials provided for user '%s'", username)
	return false
}
