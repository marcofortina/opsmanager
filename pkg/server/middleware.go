package server

import (
	"fmt"
	"net"
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
	log        *logger.LogManager
	jwtMgr     *auth.JWTManager
	cookieName string
	useJSON    bool
}

// AccessConfig holds configuration for AccessLogger
type AccessConfig struct {
	Logger     *logger.LogManager
	JWTMgr     *auth.JWTManager
	CookieName string
	UseJSON    bool // If true, logs in JSON format; if false, logs in Apache Combined Log Format
}

// NewAccessLogger creates a new AccessLogger instance
func NewAccessLogger(cfg AccessConfig) *AccessLogger {
	if cfg.CookieName == "" {
		cfg.CookieName = "jwt_token"
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}
	// Set PlainTextFormatter for access logging to avoid prefixes
	cfg.Logger.SetFormatter(&PlainTextFormatter{})
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
			al.logCombined(r, lrw, username, start)
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

// logCombined logs in Apache Combined Log Format
func (al *AccessLogger) logCombined(r *http.Request, lrw *loggingResponseWriter, username string, start time.Time) {
	// Strip port from RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // Fallback if no port
	}

	var b strings.Builder
	b.WriteString(host)     // %h: Remote IP address (no port)
	b.WriteString(" - ")    // %l: Remote logname (always "-")
	b.WriteString(username) // %u: Username
	b.WriteString(" [")
	b.WriteString(start.Format("02/Jan/2006:15:04:05 -0700")) // %t: Timestamp
	b.WriteString(`] "`)
	b.WriteString(r.Method) // %r: Method
	b.WriteString(" ")
	b.WriteString(r.URL.String()) // %r: URL
	b.WriteString(" ")
	b.WriteString(r.Proto) // %r: Protocol
	b.WriteString(`" `)
	b.WriteString(fmt.Sprintf("%d", lrw.statusCode)) // %>s: Status code
	b.WriteString(" ")
	b.WriteString(fmt.Sprintf("%d", lrw.size)) // %O: Response size
	b.WriteString(` "`)
	b.WriteString(r.Header.Get("Referer")) // %{Referer}i: Referer header
	b.WriteString(`" "`)
	b.WriteString(r.Header.Get("User-Agent")) // %{User-Agent}i: User-Agent header
	b.WriteString(`"`)
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

// loggingResponseWriter captures the HTTP status code and response size
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

// WriteHeader records the status code
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Write records the size of the response body
func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.size += int64(n)
	return n, err
}

// PlainTextFormatter is a custom formatter for plain text output
type PlainTextFormatter struct{}

// Format renders the log entry as plain text without metadata
func (f *PlainTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message + "\n"), nil
}
