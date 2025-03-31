package server

import "net/http"

// Security header constants for response hardening.
const (
	xssProtection      = "1; mode=block"                                                                                                                                                                                                   // Blocks XSS attacks
	frameOptions       = "DENY"                                                                                                                                                                                                            // Prevents framing
	contentTypeOptions = "nosniff"                                                                                                                                                                                                         // Disables MIME sniffing
	referrerPolicy     = "no-referrer"                                                                                                                                                                                                     // Limits referrer info
	permissionsPolicy  = "geolocation=(), camera=(), microphone=()"                                                                                                                                                                        // Restricts feature access
	cacheControl       = "no-store, no-cache, must-revalidate"                                                                                                                                                                             // Prevents caching
	hsts               = "max-age=31536000; includeSubDomains; preload"                                                                                                                                                                    // Enforces HTTPS for 1 year
	defaultCSP         = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';" // Basic CSP
)

// AddSecurityHeaders applies security headers to HTTP responses.
func AddSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply security headers
		w.Header().Set("X-XSS-Protection", xssProtection)
		w.Header().Set("X-Frame-Options", frameOptions)
		w.Header().Set("X-Content-Type-Options", contentTypeOptions)
		w.Header().Set("Referrer-Policy", referrerPolicy)
		w.Header().Set("Permissions-Policy", permissionsPolicy)
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("Content-Security-Policy", defaultCSP)

		// Add HSTS if TLS is active
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", hsts)
		}

		// Proceed to next handler
		next.ServeHTTP(w, r)
	})
}
