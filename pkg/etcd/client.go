package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"opsmanager/pkg/config"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Client wraps an etcd client for managing key-value operations.
type Client struct {
	client *clientv3.Client // Etcd client instance
	logger *log.Logger      // Logger for etcd operations
}

// Etcd configuration constants for timeouts and lease durations.
const (
	// DefaultDialTimeout is the etcd connection timeout (5 seconds).
	DefaultDialTimeout = 5 * time.Second

	// SessionTTL7Days is the lease duration for long-term sessions (7 days).
	SessionTTL7Days = 7 * 24 * 60 * 60 // 604800 seconds

	// SessionTTL5Minutes is the lease duration for short-term sessions (5 minutes).
	SessionTTL5Minutes = 5 * 60 // 300 seconds
)

// NewClient initializes a new etcd client with the provided configuration.
func NewClient(cfg *config.Config, logger *log.Logger) (*Client, error) {
	// Configure etcd client
	etcdCfg := clientv3.Config{
		Endpoints:   cfg.Etcd.Endpoints, // Etcd server endpoints
		DialTimeout: DefaultDialTimeout, // Connection timeout
	}

	// Enable TLS if configured
	if cfg.Etcd.EnableTLS {
		tlsConfig, err := loadTLSConfig(cfg.Etcd.TLSCertFile, cfg.Etcd.TLSKeyFile, cfg.Server.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS configuration: %v", err)
		}
		etcdCfg.TLS = tlsConfig // TLS configuration for secure connection
	}

	// Initialize etcd client
	client, err := clientv3.New(etcdCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize etcd client: %v", err)
	}

	return &Client{
		client: client, // Etcd client instance
		logger: logger, // Logger for operations
	}, nil
}

// loadTLSConfig creates a TLS configuration from certificate files.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	// Load client certificate and key pair
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key pair: %v", err)
	}

	// Load CA certificate
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	// Build TLS configuration
	return &tls.Config{
		Certificates: []tls.Certificate{cert}, // Client certificate and key pair
		RootCAs:      caCertPool,              // CA certificate pool for verification
	}, nil
}

// StoreSession stores a key-value pair in etcd with an optional lease duration in seconds.
func (c *Client) StoreSession(ctx context.Context, key, value string, ttl ...int64) error {
	// Check if a TTL is provided
	var opts []clientv3.OpOption
	if len(ttl) > 0 {
		// Grant a lease with the specified TTL in seconds
		lease, err := c.client.Grant(ctx, ttl[0])
		if err != nil {
			c.logger.Printf("Failed to grant %d-second lease for session %s: %v", ttl[0], key, err)
			return err
		}
		opts = append(opts, clientv3.WithLease(lease.ID))
	}

	// Store the key-value pair
	_, err := c.client.Put(ctx, key, value, opts...)
	if err != nil {
		if len(ttl) > 0 {
			c.logger.Printf("Failed to store session %s with %d-second lease: %v", key, ttl[0], err)
		} else {
			c.logger.Printf("Failed to store session %s without lease: %v", key, err)
		}
		return err
	}

	// Log successful storage
	if len(ttl) > 0 {
		c.logger.Printf("Stored session %s with %d-second lease", key, ttl[0])
	} else {
		c.logger.Printf("Stored session %s without lease", key)
	}
	return nil
}

// GetSession retrieves a session value from etcd by key.
func (c *Client) GetSession(ctx context.Context, key string) (string, error) {
	// Fetch the value from etcd
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		c.logger.Printf("Failed to retrieve session %s: %v", key, err)
		return "", err
	}

	// Return empty string if key not found
	if len(resp.Kvs) == 0 {
		c.logger.Printf("Session %s not found", key)
		return "", nil
	}

	// Return the stored value
	return string(resp.Kvs[0].Value), nil
}

// DeleteSession removes a session key and its associated lease from etcd.
func (c *Client) DeleteSession(ctx context.Context, key string) error {
	// Check if the key exists and get its lease ID
	resp, err := c.client.Get(ctx, key)
	if err != nil {
		c.logger.Printf("Failed to check session %s for lease: %v", key, err)
		return err
	}

	// Extract lease ID if the key exists
	var leaseID clientv3.LeaseID
	if len(resp.Kvs) > 0 {
		leaseID = clientv3.LeaseID(resp.Kvs[0].Lease)
	}

	// Delete the key
	delResp, err := c.client.Delete(ctx, key)
	if err != nil {
		c.logger.Printf("Failed to delete session %s: %v", key, err)
		return err
	}

	// Revoke the lease if it exists
	if leaseID != 0 {
		_, err = c.client.Revoke(ctx, leaseID)
		if err != nil {
			c.logger.Printf("Failed to revoke lease %d for session %s: %v", leaseID, key, err)
			return err
		}
		c.logger.Printf("Deleted session %s and revoked lease %d, removed %d keys", key, leaseID, delResp.Deleted)
	} else {
		c.logger.Printf("Deleted session %s (no lease), removed %d keys", key, delResp.Deleted)
	}

	return nil
}
