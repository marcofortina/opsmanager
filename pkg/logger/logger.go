package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// LogManager wraps logrus for structured logging
type LogManager struct {
	*logrus.Logger
}

// NewLogManager creates a new log manager instance based on the specified log level and formatter
func NewLogManager(level string, formatter logrus.Formatter) *LogManager {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	if formatter == nil {
		l.SetFormatter(&logrus.JSONFormatter{}) // Default to JSON if no formatter provided
	} else {
		l.SetFormatter(formatter)
	}

	// Set log level based on the string input
	switch level {
	case "debug":
		l.SetLevel(logrus.DebugLevel)
		l.Debug("Log manager initialized with debug level")
	case "info":
		l.SetLevel(logrus.InfoLevel)
		l.Info("Log manager initialized with info level")
	case "warn":
		l.SetLevel(logrus.WarnLevel)
		l.Warn("Log manager initialized with warn level")
	case "error":
		l.SetLevel(logrus.ErrorLevel)
		l.Error("Log manager initialized with error level")
	default:
		l.SetLevel(logrus.InfoLevel)
		l.Warnf("Invalid log level '%s', defaulting to info", level)
	}

	return &LogManager{l}
}

// Default provides a fallback log manager with info level and JSON formatter
func Default() *LogManager {
	return NewLogManager("info", nil)
}
