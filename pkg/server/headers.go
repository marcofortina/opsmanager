package server

import (
	"net/http"

	"opsmanager/pkg/logger"
)

// SecurityHeaders manages security headers for HTTP responses
type SecurityHeaders struct {
	headers map[string]string
	csp     string
	hsts    string
	log     *logger.LogManager
}

// SecurityConfig holds configuration for security headers
type SecurityConfig struct {
	CSP    string             // Content-Security-Policy (optional override)
	HSTS   string             // Strict-Transport-Security (optional override)
	Logger *logger.LogManager // Optional log manager
}

// Default security header values
var defaultHeaders = map[string]string{
	"X-XSS-Protection":       "1; mode=block",
	"X-Frame-Options":        "DENY",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy":        "no-referrer",
	"Permissions-Policy":     "geolocation=(), camera=(), microphone=()",
	"Cache-Control":          "no-store, no-cache, must-revalidate",
}

const (
	defaultCSP  = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
	defaultHSTS = "max-age=31536000; includeSubDomains; preload"
)

// NewSecurityHeaders creates a new SecurityHeaders instance
func NewSecurityHeaders(cfg SecurityConfig) *SecurityHeaders {
	headers := make(map[string]string)
	for k, v := range defaultHeaders {
		headers[k] = v
	}

	csp := defaultCSP
	if cfg.CSP != "" {
		csp = cfg.CSP
	}

	hsts := defaultHSTS
	if cfg.HSTS != "" {
		hsts = cfg.HSTS
	}

	return &SecurityHeaders{
		headers: headers,
		csp:     csp,
		hsts:    hsts,
		log:     cfg.Logger,
	}
}

// Middleware applies security headers to HTTP responses
func (sh *SecurityHeaders) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range sh.headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Security-Policy", sh.csp)

		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", sh.hsts)
			if sh.log != nil {
				sh.log.Debug("Applied HSTS header for TLS request")
			}
		}

		if sh.log != nil {
			sh.log.Debugf("Applied security headers to %s", r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}
