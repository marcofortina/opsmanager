package config

import (
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	Server struct {
		ListenAddress string `yaml:"listen_address"`  // Server listen address
		Port          string `yaml:"port"`            // Server port
		EnableTLS     bool   `yaml:"enable_tls"`      // Enable TLS for server
		TLSCertFile   string `yaml:"tls_cert_file"`   // TLS certificate file
		TLSKeyFile    string `yaml:"tls_key_file"`    // TLS private key file
		TLSCAFile     string `yaml:"tls_ca_file"`     // TLS CA certificate file
		TLSMinVersion string `yaml:"tls_min_version"` // Minimum TLS version (TLSv1.1, TLSv1.2, TLSv1.3)
	} `yaml:"server"`
	Etcd struct {
		Endpoints   []string `yaml:"endpoints"`     // Etcd connection endpoints
		EnableTLS   bool     `yaml:"enable_tls"`    // Enable TLS for etcd
		TLSCertFile string   `yaml:"tls_cert_file"` // Etcd TLS certificate file
		TLSKeyFile  string   `yaml:"tls_key_file"`  // Etcd TLS private key file
	} `yaml:"etcd"`
	Encryption struct {
		Key string `yaml:"key"` // AES encryption key
	} `yaml:"encryption"`
	TwoFactor struct {
		Enabled bool   `yaml:"enabled"` // Enable two-factor authentication
		Secret  string `yaml:"secret"`  // Two-factor authentication secret
	} `yaml:"two_factor"`
	Logging struct {
		DebugMode  bool   `yaml:"debug_mode"`  // Enable debug logging
		AccessFile string `yaml:"access_file"` // Access log file path
	} `yaml:"logging"`
}

// Default configuration values
const (
	defaultListenAddress = "0.0.0.0"    // Default server listen address (all interfaces)
	defaultPort          = "8080"       // Default server port
	defaultAccessFile    = "access.log" // Default access log file path
	defaultTLSMinVersion = "TLSv1.2"    // Default minimum TLS version
	aesKeyLength         = 32           // Required AES key length in bytes
)

// Valid TLS versions
var validTLSVersions = []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	// Read configuration file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML into Config struct
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// Process and validate AES encryption key
	if err := processAESKey(&cfg); err != nil {
		return nil, err
	}

	// Set default values if not specified
	setDefaultValues(&cfg)

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// processAESKey decodes and validates the AES encryption key
func processAESKey(cfg *Config) error {
	var aesKeyBytes []byte
	if len(cfg.Encryption.Key) == 64 {
		var err error
		aesKeyBytes, err = hex.DecodeString(cfg.Encryption.Key)
		if err != nil {
			return fmt.Errorf("failed to decode hex-encoded AES key: %v", err)
		}
	} else {
		aesKeyBytes = []byte(cfg.Encryption.Key)
	}

	// Ensure AES key is 32 bytes
	if len(aesKeyBytes) != aesKeyLength {
		return fmt.Errorf("invalid AES key length: got %d bytes, expected %d", len(aesKeyBytes), aesKeyLength)
	}
	cfg.Encryption.Key = string(aesKeyBytes)
	return nil
}

// setDefaultValues applies default values to unspecified fields
func setDefaultValues(cfg *Config) {
	if cfg.Server.ListenAddress == "" {
		cfg.Server.ListenAddress = defaultListenAddress
	}
	if cfg.Server.Port == "" {
		cfg.Server.Port = defaultPort
	}
	if cfg.Logging.AccessFile == "" {
		cfg.Logging.AccessFile = defaultAccessFile
	}
	if cfg.Server.EnableTLS && cfg.Server.TLSMinVersion == "" {
		cfg.Server.TLSMinVersion = defaultTLSMinVersion
	}
}

// validateConfig checks the configuration for required fields and valid values
func validateConfig(cfg *Config) error {
	// Ensure two-factor secret is present if 2FA is enabled
	if cfg.TwoFactor.Enabled && cfg.TwoFactor.Secret == "" {
		return fmt.Errorf("two_factor.secret is required when two_factor.enabled is true")
	}

	// Validate TLS minimum version if TLS is enabled
	if cfg.Server.EnableTLS {
		valid := false
		for _, v := range validTLSVersions {
			if cfg.Server.TLSMinVersion == v {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid tls_min_version '%s'; must be one of %v", cfg.Server.TLSMinVersion, validTLSVersions)
		}
	}

	return nil
}
