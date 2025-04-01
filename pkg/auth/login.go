package auth

import (
	"errors"

	"opsmanager/pkg/logger"
)

// LoginManager manages user authentication
type LoginManager struct {
	log       *logger.LogManager
	validUser string
	validPass string
}

// NewLoginManager initializes a new LoginManager with credentials
func NewLoginManager(log *logger.LogManager, username, password string) (*LoginManager, error) {
	if username == "" || password == "" {
		return nil, errors.New("username and password cannot be empty")
	}
	return &LoginManager{
		log:       log,
		validUser: username,
		validPass: password,
	}, nil
}

// VerifyCredentials verifies the provided username and password
func (m *LoginManager) VerifyCredentials(username, password string) bool {
	if username == "" || password == "" {
		if m.log != nil {
			m.log.Warn("Empty credentials provided")
		}
		return false
	}

	if username == m.validUser && password == m.validPass {
		if m.log != nil {
			m.log.Infof("Authentication successful for user: %s", username)
		}
		return true
	}

	if m.log != nil {
		m.log.Warnf("Authentication failed for user: %s", username)
	}
	return false
}
