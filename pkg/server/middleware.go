package server

import (
	"net/http"
	"strings"
	"time"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/logger"
	"opsmanager/pkg/middleware"

	"github.com/sirupsen/logrus"
)

// AccessLogger logs HTTP requests with user and timing info
type AccessLogger struct {
	log        *logger.Logger
	jwtMgr     *auth.JWTManager
	cookieName string
	useJSON    bool
}

// AccessConfig holds configuration for AccessLogger
type AccessConfig struct {
	Logger     *logger.Logger
	JWTMgr     *auth.JWTManager
	CookieName string
	UseJSON    bool // If true, logs in JSON format
}

// NewAccessLogger creates a new AccessLogger instance
func NewAccessLogger(cfg AccessConfig) *AccessLogger {
	if cfg.CookieName == "" {
		cfg.CookieName = "jwt_token"
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}
	return &AccessLogger{
		log:        cfg.Logger,
		jwtMgr:     cfg.JWTMgr,
		cookieName: cfg.CookieName,
		useJSON:    cfg.UseJSON,
	}
}

// Middleware returns the access logging middleware
func (al *AccessLogger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		username := al.getUsername(r)
		next.ServeHTTP(lrw, r)

		if al.useJSON {
			al.logJSON(r, lrw.statusCode, username, start)
		} else {
			al.logCommon(r, lrw.statusCode, username, start)
		}
	})
}

// getUsername extracts the username from request or context
func (al *AccessLogger) getUsername(r *http.Request) string {
	// Check context first (from auth middleware)
	if username, ok := middleware.GetUsernameFromContext(r.Context()); ok {
		return username
	}

	// Check login form for POST /login
	if r.Method == http.MethodPost && r.URL.Path == "/login" {
		if r.ParseForm() == nil {
			if username := r.FormValue("username"); username != "" {
				return username
			}
		}
	}

	// Check JWT cookie
	if cookie, err := r.Cookie(al.cookieName); err == nil {
		if username, err := al.jwtMgr.GetUsernameFromToken(cookie.Value); err == nil {
			return username
		}
	}

	return "-"
}

// logCommon logs in Common Log Format
func (al *AccessLogger) logCommon(r *http.Request, statusCode int, username string, start time.Time) {
	var b strings.Builder
	b.WriteString(r.RemoteAddr)
	b.WriteString(" - ")
	b.WriteString(username)
	b.WriteString(" [")
	b.WriteString(time.Now().Format("02/Jan/2006:15:04:05 -0700"))
	b.WriteString(`] "`)
	b.WriteString(r.Method)
	b.WriteString(" ")
	b.WriteString(r.URL.String())
	b.WriteString(`" `)
	b.WriteString(http.StatusText(statusCode))
	b.WriteString(" ")
	b.WriteString(time.Since(start).String())
	al.log.Info(b.String())
}

// logJSON logs in JSON format
func (al *AccessLogger) logJSON(r *http.Request, statusCode int, username string, start time.Time) {
	duration := time.Since(start)
	al.log.WithFields(logrus.Fields{
		"remote_addr": r.RemoteAddr,
		"username":    username,
		"time":        time.Now().Format(time.RFC3339),
		"method":      r.Method,
		"url":         r.URL.String(),
		"status":      statusCode,
		"duration":    duration.String(),
	}).Info("HTTP request")
}

// loggingResponseWriter captures the HTTP status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader records the status code
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
