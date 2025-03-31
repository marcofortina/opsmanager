package config

import (
	"encoding/hex"
	"fmt"
	"strings"

	"opsmanager/pkg/logger"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	Server     ServerConfig     `mapstructure:"server"`
	Etcd       EtcdConfig       `mapstructure:"etcd"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	TwoFactor  TwoFactorConfig  `mapstructure:"two_factor"`
	Logging    LoggingConfig    `mapstructure:"logging"`
}

// ServerConfig holds server settings
type ServerConfig struct {
	ListenAddress string    `mapstructure:"listen_address"`
	Port          string    `mapstructure:"port"`
	EnableTLS     bool      `mapstructure:"enable_tls"`
	TLS           TLSConfig `mapstructure:"tls"`
}

// TLSConfig holds TLS settings
type TLSConfig struct {
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	CAFile     string `mapstructure:"ca_file"`
	MinVersion string `mapstructure:"min_version"`
}

// EtcdConfig holds etcd settings
type EtcdConfig struct {
	Endpoints []string  `mapstructure:"endpoints"`
	EnableTLS bool      `mapstructure:"enable_tls"`
	TLS       TLSConfig `mapstructure:"tls"` // Aggiornato con sottostruttura TLS
}

// EncryptionConfig holds encryption settings
type EncryptionConfig struct {
	Key string `mapstructure:"key"`
}

// TwoFactorConfig holds 2FA settings
type TwoFactorConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Secret  string `mapstructure:"secret"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	DebugMode  bool   `mapstructure:"debug_mode"`
	AccessFile string `mapstructure:"access_file"`
	Level      string `mapstructure:"level"`
}

// Default configuration values aligned with new config.yaml
var defaults = map[string]interface{}{
	"server.listen_address":  "0.0.0.0",
	"server.port":            ":8443",
	"server.enable_tls":      true,
	"server.tls.cert_file":   "certs/server-cert.pem",
	"server.tls.key_file":    "certs/server-key.pem",
	"server.tls.ca_file":     "certs/ca-cert.pem",
	"server.tls.min_version": "TLSv1.3",
	"etcd.endpoints":         []string{"localhost:2379"},
	"etcd.enable_tls":        true,
	"etcd.tls.cert_file":     "certs/client-cert.pem", // Aggiornato
	"etcd.tls.key_file":      "certs/client-key.pem",  // Aggiornato
	"logging.debug_mode":     true,
	"logging.access_file":    "logs/access.log",
	"logging.level":          "info",
	"two_factor.enabled":     true,
}

// ValidTLSVersions maps valid TLS versions
var ValidTLSVersions = map[string]struct{}{
	"TLSv1.1": {},
	"TLSv1.2": {},
	"TLSv1.3": {},
}

// ValidLogLevels maps valid log levels
var ValidLogLevels = map[string]struct{}{
	"debug": {},
	"info":  {},
	"warn":  {},
	"error": {},
}

// Load loads configuration from a YAML file and environment variables
func Load(path string, log *logger.Logger) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults
	for key, value := range defaults {
		v.SetDefault(key, value)
	}

	// Read config file, fallback to defaults if not found
	err := v.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warnf("Config file %s not found, using defaults with env overrides", path)
		} else {
			log.Errorf("Failed to read config file %s: %v", path, err)
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		log.Errorf("Failed to unmarshal config: %v", err)
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Debug: Log the loaded config
	log.Infof("Loaded config: Server=%+v, Etcd=%+v, Encryption=%+v, TwoFactor=%+v, Logging=%+v",
		cfg.Server, cfg.Etcd, cfg.Encryption, cfg.TwoFactor, cfg.Logging)

	// Process AES key
	if err := processAESKey(&cfg); err != nil {
		log.Errorf("Failed to process AES key: %v", err)
		return nil, err
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		log.Errorf("Invalid configuration: %v", err)
		return nil, err
	}

	return &cfg, nil
}

// processAESKey decodes and validates the AES encryption key
func processAESKey(cfg *Config) error {
	const aesKeyLength = 32
	var keyBytes []byte
	if len(cfg.Encryption.Key) == 64 { // Assume hex-encoded if 64 chars
		var err error
		keyBytes, err = hex.DecodeString(cfg.Encryption.Key)
		if err != nil {
			return fmt.Errorf("failed to decode hex AES key: %v", err)
		}
	} else {
		keyBytes = []byte(cfg.Encryption.Key)
	}
	if len(keyBytes) != aesKeyLength {
		return fmt.Errorf("invalid AES key length: got %d, expected %d", len(keyBytes), aesKeyLength)
	}
	cfg.Encryption.Key = string(keyBytes)
	return nil
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	if cfg.TwoFactor.Enabled && cfg.TwoFactor.Secret == "" {
		return fmt.Errorf("two_factor.secret required when enabled")
	}
	if cfg.Server.EnableTLS {
		if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
			return fmt.Errorf("TLS enabled but cert_file or key_file missing")
		}
		if _, ok := ValidTLSVersions[cfg.Server.TLS.MinVersion]; !ok {
			return fmt.Errorf("invalid tls.min_version '%s'; must be TLSv1.1, TLSv1.2, or TLSv1.3", cfg.Server.TLS.MinVersion)
		}
	}
	if cfg.Etcd.EnableTLS {
		if cfg.Etcd.TLS.CertFile == "" || cfg.Etcd.TLS.KeyFile == "" {
			return fmt.Errorf("etcd TLS enabled but cert_file or key_file missing")
		}
	}
	if _, ok := ValidLogLevels[cfg.Logging.Level]; !ok {
		return fmt.Errorf("invalid logging.level '%s'; must be debug, info, warn, or error", cfg.Logging.Level)
	}
	return nil
}
