package middleware

import (
	"context"
	"net/http"
	"strings"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/logger"
)

// AuthMiddleware enforces JWT authentication for protected routes
type AuthMiddleware struct {
	jwtMgr     *auth.JWTManager
	log        *logger.LogManager
	cookieName string
}

// AuthConfig holds configuration for AuthMiddleware
type AuthConfig struct {
	JWTMgr     *auth.JWTManager
	Logger     *logger.LogManager
	CookieName string
}

// NewAuth creates a new AuthMiddleware instance
func NewAuth(cfg AuthConfig) *AuthMiddleware {
	if cfg.CookieName == "" {
		cfg.CookieName = "jwt_token"
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}
	return &AuthMiddleware{
		jwtMgr:     cfg.JWTMgr,
		log:        cfg.Logger,
		cookieName: cfg.CookieName,
	}
}

// Middleware returns the authentication middleware
func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for OPTIONS requests
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Try cookie first
		var token string
		if cookie, err := r.Cookie(m.cookieName); err == nil {
			token = cookie.Value
		} else {
			// Fallback to Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token == "" {
			m.log.Warnf("No JWT token found for %s", r.URL.Path)
			m.redirectToLogin(w, r)
			return
		}

		claims, err := m.jwtMgr.VerifyToken(token)
		if err != nil {
			m.log.Warnf("Invalid JWT token for %s: %v", r.URL.Path, err)
			m.redirectToLogin(w, r)
			return
		}

		username, ok := claims["sub"].(string)
		if !ok {
			m.log.Warnf("No username in claims for %s", r.URL.Path)
			m.redirectToLogin(w, r)
			return
		}

		m.log.Infof("Authenticated user %s for %s", username, r.URL.Path)
		ctx := context.WithValue(r.Context(), authKey{}, username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// redirectToLogin redirects to the login page
func (m *AuthMiddleware) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// authKey is a private type for context key
type authKey struct{}

// GetUsernameFromContext retrieves the username from the request context
func GetUsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(authKey{}).(string)
	return username, ok
}
