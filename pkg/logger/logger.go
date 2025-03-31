package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus for structured logging
type Logger struct {
	*logrus.Logger
}

// New creates a new logger instance based on debug mode
func New(debugMode bool) *Logger {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.JSONFormatter{})
	if debugMode {
		l.SetLevel(logrus.DebugLevel)
		l.Debug("Debug mode enabled")
	} else {
		l.SetLevel(logrus.InfoLevel)
		l.Info("Debug mode disabled")
	}
	return &Logger{l}
}

// Default provides a fallback logger
func Default() *Logger {
	l := logrus.New()
	l.SetOutput(os.Stdout)
	l.SetFormatter(&logrus.JSONFormatter{})
	return &Logger{l}
}
