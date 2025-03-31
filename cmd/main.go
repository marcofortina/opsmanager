package main

import (
	"context"
	"flag"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"opsmanager/pkg/config"
	"opsmanager/pkg/logger"
	"opsmanager/pkg/server"
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
	// Load configuration
	log := logger.New(true) // Default debug mode until config is loaded
	log.Infof("Loading configuration from %s", configPath)
	cfg, err := config.Load(configPath, log)
	if err != nil {
		return err
	}

	// Debug: Stampa il valore di AccessFile
	log.Infof("Loaded config - AccessFile: %s", cfg.Logging.AccessFile)

	// Update logger with config settings
	log = logger.New(cfg.Logging.DebugMode)
	log.Infof("Starting server with debug mode: %v", cfg.Logging.DebugMode)

	// Initialize server
	srvCfg := server.ServerConfig{
		Config:      cfg,
		Logger:      log,
		TemplateDir: "./templates",
	}
	srv := server.New(srvCfg)

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
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("Server shutdown failed: %v", err)
		return err
	}

	log.Info("Server stopped gracefully")
	return nil
}
