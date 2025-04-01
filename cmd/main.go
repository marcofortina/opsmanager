package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"opsmanager/pkg/config"
	"opsmanager/pkg/logger"
	"opsmanager/pkg/server"

	"github.com/sirupsen/logrus"
)

// main initializes and starts the Ops Manager application
func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	shutdownTimeout := flag.Duration("shutdown-timeout", 5*time.Second, "Timeout for graceful shutdown")
	flag.Parse()

	if err := run(*configPath, *shutdownTimeout); err != nil {
		log := logger.Default()
		log.Fatalf("Application failed: %v", err)
	}
}

// run executes the main application logic
func run(configPath string, shutdownTimeout time.Duration) error {
	// Initialize logger with a default level until config is loaded
	log := logger.NewLogManager("info", &logrus.JSONFormatter{})
	log.Infof("Loading configuration from %s", configPath)

	// Load configuration
	cfg, err := config.Load(configPath, log)
	if err != nil {
		return err
	}

	// Debug: Print the value of AccessFile and Level
	log.Infof("Loaded config - AccessFile: %s, Log Level: %s", cfg.Logging.AccessFile, cfg.Logging.Level)

	// Update logger with configured level
	log = logger.NewLogManager(cfg.Logging.Level, &logrus.JSONFormatter{})
	log.Infof("Starting server with log level: %s", cfg.Logging.Level)

	// Initialize server
	srvCfg := server.ServerConfig{
		Config:      cfg,
		Logger:      log,
		TemplateDir: "./templates",
	}
	srv := server.NewServer(srvCfg)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
		close(errChan)
	}()

	// Handle graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Info("Received shutdown signal")
	case err := <-errChan:
		if err != nil {
			log.Errorf("Server failed: %v", err)
			return err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("Server shutdown failed: %v", err)
		return err
	}

	log.Info("Server stopped gracefully")
	return nil
}
