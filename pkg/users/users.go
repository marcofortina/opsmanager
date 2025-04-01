package users

import (
	"crypto/sha256"
	"fmt"

	"opsmanager/pkg/etcd"
	"opsmanager/pkg/logger"
)

// User represents a user with credentials
type User struct {
	Username string
	Password string // Hashed password
}

// UserManager manages user credentials
type UserManager struct {
	users map[string]User
	log   *logger.LogManager
	etcd  *etcd.Client
}

// NewUserManager initializes a new UserManager
func NewUserManager(log *logger.LogManager, etcd *etcd.Client) (*UserManager, error) {
	if log == nil {
		log = logger.Default()
	}
	if etcd == nil {
		return nil, fmt.Errorf("etcd client is required")
	}

	users := map[string]User{
		"admin": {
			Username: "admin",
			Password: hashPassword("secret123"),
		},
	}

	return &UserManager{
		users: users,
		log:   log,
		etcd:  etcd,
	}, nil
}

// VerifyCredentials checks if the username and password match
func (m *UserManager) VerifyCredentials(username, password string) bool {
	user, exists := m.users[username]
	if !exists {
		return false
	}
	return user.Password == hashPassword(password)
}

// hashPassword hashes a password using SHA-256
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x", hash)
}
