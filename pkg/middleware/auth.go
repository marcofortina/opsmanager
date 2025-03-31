package middleware

import (
	"log"
	"net/http"

	"opsmanager/pkg/auth"
)

// Auth enforces JWT authentication for protected routes.
func Auth(jwtMgr *auth.JWTManager, logger *log.Logger) func(http.Handler) http.Handler {
	const jwtCookieName = "jwt_token" // Name of the JWT cookie

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get JWT token from cookie
			cookie, err := r.Cookie(jwtCookieName)
			if err != nil {
				logger.Printf("No JWT token found in request to %s: %v", r.URL.Path, err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Verify token and extract claims
			claims, err := jwtMgr.VerifyToken(cookie.Value)
			if err != nil {
				logger.Printf("Invalid JWT token for %s: %v", r.URL.Path, err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			// Log successful authentication
			if username, ok := claims["sub"].(string); ok {
				logger.Printf("Authenticated user '%s' for %s", username, r.URL.Path)
			} else {
				logger.Printf("Authenticated request to %s (no username in claims)", r.URL.Path)
			}

			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
