package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/config"
	"opsmanager/pkg/etcd"
	"opsmanager/pkg/handlers"
	"opsmanager/pkg/middleware"
	"opsmanager/pkg/rsa"
)

// Server represents the web server.
type Server struct {
	http.Server                // Embedded HTTP server
	cfg         *config.Config // Server configuration
	logger      *log.Logger    // Application logger
	accessLog   *log.Logger    // Access logger for requests
}

// New initializes a new Server instance.
func New(cfg *config.Config, logger *log.Logger) *Server {
	// Open access log file
	accessFile, err := os.OpenFile(cfg.Logging.AccessFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Fatalf("Failed to open access log at %s: %v", cfg.Logging.AccessFile, err)
	}
	accessLog := log.New(accessFile, "", log.LstdFlags)

	// Initialize etcd client
	logger.Printf("Initializing etcd client")
	etcdClient, err := etcd.NewClient(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize etcd client: %v", err)
	}

	// Initialize RSA key manager with context
	logger.Printf("Initializing RSA key manager")
	ctx := context.Background()
	rsaMgr, err := rsa.NewKeyManager(ctx, logger, etcdClient, []byte(cfg.Encryption.Key))
	if err != nil {
		logger.Fatalf("Failed to initialize RSA key manager: %v", err)
	}

	// Initialize JWT manager
	logger.Printf("Initializing JWT manager")
	jwtMgr, err := auth.NewJWTManager(rsaMgr.PrivateKey())
	if err != nil {
		logger.Fatalf("Failed to initialize JWT manager: %v", err)
	}

	// Initialize CSRF manager
	logger.Printf("Initializing CSRF manager")
	csrfMgr := auth.NewCSRFManager()

	// Initialize login manager
	logger.Printf("Initializing login manager")
	loginMgr := auth.NewLoginManager(logger)

	// Initialize handlers
	logger.Printf("Initializing handlers")
	h, err := handlers.New("./templates", jwtMgr, csrfMgr, loginMgr, etcdClient, logger, cfg)
	if err != nil {
		logger.Fatalf("Failed to initialize handlers: %v", err)
	}

	// Configure HTTP multiplexer with routes
	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.Login)
	mux.HandleFunc("/logout", h.Logout)
	mux.HandleFunc("/verify-2fa", h.Verify2FA)
	mux.Handle("/dashboard", middleware.Auth(jwtMgr, logger)(http.HandlerFunc(h.Dashboard)))
	mux.Handle("/config", middleware.Auth(jwtMgr, logger)(http.HandlerFunc(h.Config)))

	// Add static file handlers
	AddStaticHandlers(mux)

	// Apply middleware for logging and security headers
	handler := AddSecurityHeaders(accessLogger(accessLog, jwtMgr, mux))

	// Set server address
	addr := cfg.Server.ListenAddress + ":" + cfg.Server.Port

	// Initialize server
	srv := &Server{
		Server: http.Server{
			Addr:    addr,
			Handler: handler,
		},
		cfg:       cfg,
		logger:    logger,
		accessLog: accessLog,
	}

	// Configure TLS if enabled
	if cfg.Server.EnableTLS {
		srv.configureTLS(cfg, logger)
	}

	return srv
}

// configureTLS sets up TLS configuration for the server.
func (s *Server) configureTLS(cfg *config.Config, logger *log.Logger) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 or higher
	}

	// Load CA certificate if specified
	if cfg.Server.TLSCAFile != "" {
		caCert, err := os.ReadFile(cfg.Server.TLSCAFile)
		if err != nil {
			logger.Fatalf("Failed to read CA file %s: %v", cfg.Server.TLSCAFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			logger.Fatalf("Failed to parse CA certificate from %s", cfg.Server.TLSCAFile)
		}
		tlsConfig.RootCAs = caCertPool
		logger.Printf("Loaded CA certificate from %s", cfg.Server.TLSCAFile)
	}

	s.TLSConfig = tlsConfig
}

// Run starts the server.
func (s *Server) Run() error {
	s.logger.Printf("Starting server on %s (TLS=%v)", s.Addr, s.cfg.Server.EnableTLS)
	defer s.accessLog.Writer().(*os.File).Close() // Close access log file on exit
	if s.cfg.Server.EnableTLS {
		return s.ListenAndServeTLS(s.cfg.Server.TLSCertFile, s.cfg.Server.TLSKeyFile)
	}
	return s.ListenAndServe()
}
