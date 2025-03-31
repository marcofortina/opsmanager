package main

import (
	"log"
	"os"
	"opsmanager/pkg/config"
	"opsmanager/pkg/server"
)

// Logger instance for the application
var logger *log.Logger

// Log level prefixes
const (
	infoPrefix  = "INFO: "  // Prefix for info-level logs
	debugPrefix = "DEBUG: " // Prefix for debug-level logs
)

// Log formatting flags
const (
	infoFlags  = log.Ldate | log.Ltime                  // Flags for info logs: date and time
	debugFlags = log.Ldate | log.Ltime | log.Lshortfile // Flags for debug logs: date, time, and file
)

// main is the entry point of the application
func main() {
	// Load configuration from config.yaml
	cfg, err := config.Load("config.yaml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger based on debug mode
	initializeLogger(cfg.Logging.DebugMode)

	// Log server startup
	logger.Printf("Starting web server with debug mode: %v", cfg.Logging.DebugMode)

	// Initialize and start the server
	srv := server.New(cfg, logger)
	if err := srv.Run(); err != nil {
		logger.Fatalf("Failed to start server: %v", err)
	}
}

// initializeLogger configures the logger based on debug mode
func initializeLogger(debugMode bool) {
	if debugMode {
		logger = log.New(os.Stdout, debugPrefix, debugFlags)
		logger.Println("Debug mode enabled")
	} else {
		logger = log.New(os.Stdout, infoPrefix, infoFlags)
		logger.Println("Debug mode disabled")
	}
}
