package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/config"
	"opsmanager/pkg/etcd"
	"opsmanager/pkg/handlers"
	"opsmanager/pkg/logger"
	"opsmanager/pkg/middleware"
	"opsmanager/pkg/rsa"
	"opsmanager/pkg/users"

	"github.com/sirupsen/logrus"
)

// Server represents the web server
type Server struct {
	httpServer    *http.Server
	cfg           *config.Config
	log           *logger.LogManager
	accessLog     *logger.LogManager
	accessFile    *os.File
	handler       *handlers.Handler
	etcdClient    *etcd.Client
	staticHandler *StaticHandler
}

// ServerConfig holds configuration for Server
type ServerConfig struct {
	Config      *config.Config
	Logger      *logger.LogManager
	TemplateDir string
}

// NewServer initializes a new Server instance
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}

	// Open access log file
	accessFile, err := os.OpenFile(cfg.Config.Logging.AccessFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		cfg.Logger.Fatalf("Failed to open access log at %s: %v", cfg.Config.Logging.AccessFile, err)
	}
	accessLog := logger.NewLogManager(cfg.Config.Logging.Level, &logrus.JSONFormatter{})
	accessLog.SetOutput(accessFile)

	// Initialize etcd client
	cfg.Logger.Infof("Initializing etcd client")
	etcdCfg := etcd.EtcdConfig{
		Endpoints:   cfg.Config.Etcd.Endpoints,
		EnableTLS:   cfg.Config.Etcd.EnableTLS,
		TLSCertFile: cfg.Config.Etcd.TLS.CertFile,
		TLSKeyFile:  cfg.Config.Etcd.TLS.KeyFile,
		TLSCAFile:   cfg.Config.Server.TLS.CAFile,
		DialTimeout: 5 * time.Second,
		Logger:      cfg.Logger,
	}
	etcdClient, err := etcd.NewClient(etcdCfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize etcd client: %v", err)
	}

	// Initialize RSA key manager
	cfg.Logger.Infof("Initializing RSA key manager")
	rsaCfg := rsa.KeyManagerConfig{
		KeySize:    rsa.DefaultKeySize,
		KeyPath:    rsa.DefaultKeyPath,
		AESKey:     []byte(cfg.Config.Encryption.Key),
		EtcdClient: etcdClient,
		Logger:     cfg.Logger,
	}
	rsaMgr, err := rsa.NewKeyManager(rsaCfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize RSA key manager: %v", err)
	}

	// Initialize JWT manager
	cfg.Logger.Infof("Initializing JWT manager")
	jwtCfg := auth.JWTConfig{
		PrivateKey: rsaMgr.PrivateKey(),
		Logger:     cfg.Logger,
	}
	jwtMgr, err := auth.NewJWTManager(jwtCfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize JWT manager: %v", err)
	}

	// Initialize CSRF manager
	cfg.Logger.Infof("Initializing CSRF manager")
	csrfMgr := auth.NewCSRFManager(auth.CSRFTokenLength, cfg.Logger)

	// Initialize user manager
	cfg.Logger.Infof("Initializing user manager")
	userMgr, err := users.NewUserManager(cfg.Logger, etcdClient)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize user manager: %v", err)
	}

	// Initialize TOTP manager
	cfg.Logger.Infof("Initializing TOTP manager")
	totpCfg := &auth.TOTPConfig{
		Interval:   auth.DefaultTOTPInterval,
		CodeLength: auth.DefaultTOTPCodeLength,
		Logger:     cfg.Logger,
		Etcd:       etcdClient,
	}
	totpMgr, err := auth.NewTOTPManager(totpCfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize TOTP manager: %v", err)
	}

	// Initialize handlers
	cfg.Logger.Infof("Initializing handlers")
	handlerCfg := handlers.HandlerConfig{
		TemplateDir: cfg.TemplateDir,
		JWTMgr:      jwtMgr,
		CSRFMgr:     csrfMgr,
		UserMgr:     userMgr,
		TotpMgr:     totpMgr,
		Etcd:        etcdClient,
		Logger:      cfg.Logger,
		Config:      cfg.Config,
		OpTimeout:   2 * time.Second,
	}
	h, err := handlers.NewHandler(handlerCfg)
	if err != nil {
		cfg.Logger.Fatalf("Failed to initialize handlers: %v", err)
	}

	// Initialize static handler
	staticHandler := NewStaticHandler(StaticConfig{
		Dir:    "./static",
		Logger: cfg.Logger,
	})

	// Configure routes
	mux := http.NewServeMux()
	mux.HandleFunc("/login", h.Login)
	mux.HandleFunc("/logout", h.Logout)
	mux.HandleFunc("/verify-2fa", h.Verify2FA)
	authMw := middleware.NewAuth(middleware.AuthConfig{JWTMgr: jwtMgr, Logger: cfg.Logger})
	mux.Handle("/dashboard", authMw.Middleware(http.HandlerFunc(h.Dashboard)))
	mux.Handle("/config", authMw.Middleware(http.HandlerFunc(h.Config)))
	staticHandler.AddStaticHandlers(mux)

	// Apply middleware
	accessCfg := AccessConfig{
		Logger:     accessLog,
		JWTMgr:     jwtMgr,
		CookieName: "jwt_token",
		UseJSON:    false,
	}
	accessMw := NewAccessLogger(accessCfg)
	securityMw := NewSecurityHeaders(SecurityConfig{Logger: cfg.Logger})
	handler := securityMw.Middleware(accessMw.Middleware(mux))

	// Initialize server
	addr := cfg.Config.Server.ListenAddress + ":" + cfg.Config.Server.Port
	srv := &Server{
		httpServer: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
		cfg:           cfg.Config,
		log:           cfg.Logger,
		accessLog:     accessLog,
		accessFile:    accessFile,
		handler:       h,
		etcdClient:    etcdClient,
		staticHandler: staticHandler,
	}

	if cfg.Config.Server.EnableTLS {
		srv.configureTLS()
	}

	return srv
}

// configureTLS sets up TLS configuration
func (s *Server) configureTLS() {
	tlsConfig := &tls.Config{
		MinVersion: tlsVersionFromString(s.cfg.Server.TLS.MinVersion),
	}

	if s.cfg.Server.TLS.CAFile != "" {
		caCert, err := os.ReadFile(s.cfg.Server.TLS.CAFile)
		if err != nil {
			s.log.Fatalf("Failed to read CA file %s: %v", s.cfg.Server.TLS.CAFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			s.log.Fatalf("Failed to parse CA certificate from %s", s.cfg.Server.TLS.CAFile)
		}
		tlsConfig.RootCAs = caCertPool
		s.log.Infof("Loaded CA certificate from %s", s.cfg.Server.TLS.CAFile)
	}

	s.httpServer.TLSConfig = tlsConfig
}

// tlsVersionFromString converts TLS version string to uint16
func tlsVersionFromString(version string) uint16 {
	switch version {
	case "TLSv1.1":
		return tls.VersionTLS11
	case "TLSv1.2":
		return tls.VersionTLS12
	case "TLSv1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12 // Default to TLS 1.2
	}
}

// Run starts the server
func (s *Server) Run() error {
	s.log.Infof("Starting server on %s (TLS=%v)", s.httpServer.Addr, s.cfg.Server.EnableTLS)
	if s.cfg.Server.EnableTLS {
		return s.httpServer.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
		s.log.Errorf("Server shutdown failed: %v", err)
		shutdownErr = err
	}

	// Close etcd client
	if s.etcdClient != nil {
		if err := s.etcdClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Errorf("Failed to close etcd client: %v", err)
			if shutdownErr == nil {
				shutdownErr = err
			}
		}
	}

	// Close handler
	if s.handler != nil {
		if err := s.handler.Close(); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Errorf("Failed to close handlers: %v", err)
			if shutdownErr == nil {
				shutdownErr = err
			}
		}
	}

	// Close access log file
	if s.accessFile != nil {
		if err := s.accessFile.Close(); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Errorf("Failed to close access log file: %v", err)
			if shutdownErr == nil {
				shutdownErr = err
			}
		}
	}

	s.log.Info("Server shut down gracefully")
	return shutdownErr
}
