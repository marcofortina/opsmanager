package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"opsmanager/pkg/logger"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Client wraps an etcd client
type Client struct {
	client *clientv3.Client
	log    *logger.Logger
}

// EtcdConfig holds etcd client configuration
type EtcdConfig struct {
	Endpoints   []string
	EnableTLS   bool
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
	DialTimeout time.Duration
	Logger      *logger.Logger
}

// Session TTL constants
const (
	DefaultDialTimeout = 5 * time.Second  // Default connection timeout
	SessionTTL7Days    = 7 * 24 * 60 * 60 // 7 days in seconds
	SessionTTL5Minutes = 5 * 60           // 5 minutes in seconds
	DefaultOpTimeout   = 2 * time.Second  // Default operation timeout
)

// NewClient initializes a new etcd client
func NewClient(cfg EtcdConfig) (*Client, error) {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}

	var tlsConfig *tls.Config
	if cfg.EnableTLS {
		tlsConfig = &tls.Config{}
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			cfg.Logger.Errorf("Failed to load etcd TLS cert/key: %v", err)
			return nil, fmt.Errorf("failed to load etcd TLS cert/key: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		if cfg.TLSCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				cfg.Logger.Errorf("Failed to read etcd CA file %s: %v", cfg.TLSCAFile, err)
				return nil, fmt.Errorf("failed to read etcd CA file: %v", err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse etcd CA certificate")
			}
			tlsConfig.RootCAs = caCertPool
		}
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		TLS:         tlsConfig,
	})
	if err != nil {
		cfg.Logger.Errorf("Failed to connect to etcd: %v", err)
		return nil, fmt.Errorf("failed to connect to etcd: %v", err)
	}

	return &Client{
		client: client,
		log:    cfg.Logger,
	}, nil
}

// StoreSession stores a key-value pair with an optional lease
func (c *Client) StoreSession(ctx context.Context, key, value string, ttl ...int64) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultOpTimeout)
	defer cancel()

	var opts []clientv3.OpOption
	if len(ttl) > 0 {
		lease, err := c.client.Grant(ctx, ttl[0])
		if err != nil {
			c.log.Errorf("Failed to grant %d-second lease for %s: %v", ttl[0], key, err)
			return err
		}
		opts = append(opts, clientv3.WithLease(lease.ID))
	}

	_, err := c.client.Put(ctx, key, value, opts...)
	if err != nil {
		c.log.Errorf("Failed to store session %s: %v", key, err)
		return err
	}

	if len(ttl) > 0 {
		c.log.Infof("Stored session %s with %d-second lease", key, ttl[0])
	} else {
		c.log.Infof("Stored session %s without lease", key)
	}
	return nil
}

// GetSession retrieves a session value by key
func (c *Client) GetSession(ctx context.Context, key string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultOpTimeout)
	defer cancel()

	resp, err := c.client.Get(ctx, key)
	if err != nil {
		c.log.Errorf("Failed to retrieve session %s: %v", key, err)
		return "", err
	}

	if len(resp.Kvs) == 0 {
		c.log.Debugf("Session %s not found", key)
		return "", nil
	}

	return string(resp.Kvs[0].Value), nil
}

// DeleteSession removes a session key and its lease
func (c *Client) DeleteSession(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultOpTimeout)
	defer cancel()

	resp, err := c.client.Get(ctx, key)
	if err != nil {
		c.log.Errorf("Failed to check session %s: %v", key, err)
		return err
	}

	var leaseID clientv3.LeaseID
	if len(resp.Kvs) > 0 {
		leaseID = clientv3.LeaseID(resp.Kvs[0].Lease)
	}

	delResp, err := c.client.Delete(ctx, key)
	if err != nil {
		c.log.Errorf("Failed to delete session %s: %v", key, err)
		return err
	}

	if leaseID != 0 {
		_, err = c.client.Revoke(ctx, leaseID)
		if err != nil {
			c.log.Errorf("Failed to revoke lease %d for %s: %v", leaseID, key, err)
			return err
		}
		c.log.Infof("Deleted session %s and revoked lease %d, removed %d keys", key, leaseID, delResp.Deleted)
	} else {
		c.log.Infof("Deleted session %s (no lease), removed %d keys", key, delResp.Deleted)
	}

	return nil
}

// Close shuts down the etcd client
func (c *Client) Close() error {
	err := c.client.Close()
	if err != nil {
		c.log.Errorf("Failed to close etcd client: %v", err)
	}
	return err
}
