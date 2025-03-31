package server

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"opsmanager/pkg/auth"
)

// accessLogger logs HTTP requests with user and timing information.
func accessLogger(logger *log.Logger, jwtMgr *auth.JWTManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to track status
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Capture start time
		start := time.Now()

		// Get username from request
		username := getUsername(r, jwtMgr)

		// Process request
		next.ServeHTTP(lrw, r)

		// Log request in Common Log Format
		logLine := formatLogLine(r, lrw.statusCode, username, start)
		logger.Println(logLine)
	})
}

// getUsername extracts the username from the request or returns "-".
func getUsername(r *http.Request, jwtMgr *auth.JWTManager) string {
	// Check login form for POST /login
	if r.Method == http.MethodPost && r.URL.Path == "/login" {
		if err := r.ParseForm(); err == nil {
			if username := r.FormValue("username"); username != "" {
				return username
			}
		}
	}

	// Check JWT cookie
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if username, err := jwtMgr.GetUsernameFromToken(cookie.Value); err == nil {
			return username
		}
	}

	return "-"
}

// formatLogLine creates a log entry in Common Log Format.
func formatLogLine(r *http.Request, statusCode int, username string, start time.Time) string {
	ip := r.RemoteAddr
	timestamp := time.Now().Format("02/Jan/2006:15:04:05 -0700")
	method := r.Method
	url := r.URL.String()
	duration := time.Since(start)
	return fmt.Sprintf(`%s - %s [%s] "%s %s" %d %s`, ip, username, timestamp, method, url, statusCode, duration)
}

// loggingResponseWriter captures the HTTP status code.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader records the status code before writing it.
func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}
