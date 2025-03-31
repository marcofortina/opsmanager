package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/config"
	"opsmanager/pkg/etcd"
)

// Handler manages HTTP request handlers.
type Handler struct {
	templateDir string             // Directory for HTML templates
	jwtMgr      *auth.JWTManager   // Manages JWT authentication
	csrfMgr     *auth.CSRFManager  // Generates CSRF tokens
	loginMgr    *auth.LoginManager // Verifies user credentials
	etcd        *etcd.Client       // Stores session data in etcd
	logger      *log.Logger        // Logs handler operations
	cfg         *config.Config     // Application configuration
}

// New initializes a new Handler instance.
func New(templateDir string, jwtMgr *auth.JWTManager, csrfMgr *auth.CSRFManager, loginMgr *auth.LoginManager, etcd *etcd.Client, logger *log.Logger, cfg *config.Config) (*Handler, error) {
	return &Handler{
		templateDir: templateDir,
		jwtMgr:      jwtMgr,
		csrfMgr:     csrfMgr,
		loginMgr:    loginMgr,
		etcd:        etcd,
		logger:      logger,
		cfg:         cfg,
	}, nil
}

// Login handles login page rendering and authentication.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.handleLoginPost(w, r)
		return
	}
	h.handleLoginGet(w, r)
}

// handleLoginGet renders the login page with a CSRF token.
func (h *Handler) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check if user is already authenticated
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if _, err := h.jwtMgr.VerifyToken(cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	// Generate and store CSRF token
	csrfToken, err := h.csrfMgr.GenerateToken()
	if err != nil {
		h.logger.Printf("Failed to generate CSRF token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := h.etcd.StoreSession(r.Context(), "csrf:"+csrfToken, csrfToken, etcd.SessionTTL5Minutes); err != nil {
		h.logger.Printf("Failed to store CSRF token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Render login template
	tmpl, err := template.ParseFiles(filepath.Join(h.templateDir, "login.html"))
	if err != nil {
		h.logger.Printf("Failed to parse login.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, map[string]string{"CSRFToken": csrfToken}); err != nil {
		h.logger.Printf("Failed to execute login template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleLoginPost processes login form submission.
func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.sendJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract form values
	username := r.FormValue("username")
	password := r.FormValue("password")
	csrfToken := r.FormValue("csrf_token")

	// Verify CSRF token
	storedToken, err := h.etcd.GetSession(r.Context(), "csrf:"+csrfToken)
	if err != nil || storedToken != csrfToken {
		h.logger.Printf("Invalid or expired CSRF token for %s", username)
		h.sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Verify credentials
	if !h.loginMgr.VerifyCredentials(username, password) {
		h.logger.Printf("Authentication failed for %s: invalid credentials", username)
		h.sendJSONError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Clean up CSRF token
	if err := h.etcd.DeleteSession(r.Context(), "csrf:"+csrfToken); err != nil {
		h.logger.Printf("Failed to delete CSRF token for %s: %v", username, err)
	}

	// Handle authentication based on 2FA setting
	if !h.cfg.TwoFactor.Enabled {
		h.completeLogin(w, username)
		return
	}
	h.initiate2FA(w, r, username)
}

// completeLogin generates a long-term JWT and completes authentication.
func (h *Handler) completeLogin(w http.ResponseWriter, username string) {
	const tokenTTL = 7 * 24 * 60 * 60 // 7 days in seconds
	token, err := h.jwtMgr.GenerateToken(username, tokenTTL*time.Second)
	if err != nil {
		h.logger.Printf("Failed to generate token for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}
	if err := h.etcd.StoreSession(context.Background(), "session:"+username, token, etcd.SessionTTL7Days); err != nil {
		h.logger.Printf("Failed to store session for %s: %v", username, err)
		h.sendJSONError(w, "Session storage failed", http.StatusInternalServerError)
		return
	}
	h.setJWTCookie(w, token)
	h.logger.Printf("User %s authenticated successfully without 2FA", username)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"redirect": "/dashboard",
	})
}

// initiate2FA starts the 2FA process with a temporary token.
func (h *Handler) initiate2FA(w http.ResponseWriter, r *http.Request, username string) {
	const tempTokenTTL = 5 * 60 // 5 minutes in seconds
	tempToken, err := h.jwtMgr.GenerateToken(username, tempTokenTTL*time.Second)
	if err != nil {
		h.logger.Printf("Failed to generate temp token for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Generate and store CSRF token for 2FA
	csrfToken2FA, err := h.csrfMgr.GenerateToken()
	if err != nil {
		h.logger.Printf("Failed to generate CSRF token for 2FA: %v", err)
		h.sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := h.etcd.StoreSession(r.Context(), "csrf_2fa:"+csrfToken2FA, csrfToken2FA, etcd.SessionTTL5Minutes); err != nil {
		h.logger.Printf("Failed to store CSRF token for 2FA: %v", err)
		h.sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := h.etcd.StoreSession(r.Context(), "temp_auth:"+username, tempToken, etcd.SessionTTL5Minutes); err != nil {
		h.logger.Printf("Failed to store temp auth for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	h.logger.Printf("User %s passed password check, awaiting 2FA", username)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requires2FA":  true,
		"tempToken":    tempToken,
		"csrfToken2FA": csrfToken2FA,
	})
}

// Verify2FA processes 2FA verification.
func (h *Handler) Verify2FA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Redirect if already authenticated
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if _, err := h.jwtMgr.VerifyToken(cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	if r.Method != http.MethodPost {
		h.sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.sendJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract form values
	username := r.FormValue("username")
	tempToken := r.FormValue("tempToken")
	totpCode := r.FormValue("otp")
	csrfToken2FA := r.FormValue("csrf_token_2fa")

	// Verify CSRF token
	storedCSRF, err := h.etcd.GetSession(r.Context(), "csrf_2fa:"+csrfToken2FA)
	if err != nil || storedCSRF != csrfToken2FA {
		h.logger.Printf("Invalid or expired 2FA CSRF token for %s", username)
		h.sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Verify temp token
	claims, err := h.jwtMgr.VerifyToken(tempToken)
	if err != nil || claims["sub"] != username {
		h.logger.Printf("Invalid or expired temp token for %s: %v", username, err)
		h.sendJSONError(w, "Session expired or invalid", http.StatusUnauthorized)
		return
	}
	storedToken, err := h.etcd.GetSession(r.Context(), "temp_auth:"+username)
	if err != nil || storedToken != tempToken {
		h.logger.Printf("Temp token mismatch or not found for %s", username)
		h.sendJSONError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Verify TOTP code
	if !auth.VerifyTOTP(h.cfg.TwoFactor.Secret, totpCode) {
		h.logger.Printf("2FA failed for %s: invalid TOTP code", username)
		h.sendJSONError(w, "Invalid 2FA code", http.StatusUnauthorized)
		return
	}

	// Generate long-term token and complete login
	h.completeLogin(w, username)

	// Clean up temporary data
	if err := h.etcd.DeleteSession(r.Context(), "temp_auth:"+username); err != nil {
		h.logger.Printf("Failed to delete temp auth for %s: %v", username, err)
	}
	if err := h.etcd.DeleteSession(r.Context(), "csrf_2fa:"+csrfToken2FA); err != nil {
		h.logger.Printf("Failed to delete 2FA CSRF token for %s: %v", username, err)
	}
}

// Logout clears the session and redirects to login.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if claims, err := h.jwtMgr.VerifyToken(cookie.Value); err == nil {
			if username, ok := claims["sub"].(string); ok {
				if err := h.etcd.DeleteSession(r.Context(), "session:"+username); err != nil {
					h.logger.Printf("Failed to delete session for %s: %v", username, err)
				}
				h.logger.Printf("User %s logged out", username)
			}
		}
	}

	// Clear JWT cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.EnableTLS,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Dashboard serves the dashboard page.
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	h.logger.Printf("Serving dashboard")
	tmpl, err := template.ParseFiles(filepath.Join(h.templateDir, "dashboard.html"))
	if err != nil {
		h.logger.Printf("Failed to parse dashboard.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		h.logger.Printf("Failed to execute dashboard template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Config serves the config page.
func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	h.logger.Printf("Serving config")
	tmpl, err := template.ParseFiles(filepath.Join(h.templateDir, "config.html"))
	if err != nil {
		h.logger.Printf("Failed to parse config.html: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		h.logger.Printf("Failed to execute config template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// setJWTCookie sets a secure JWT cookie.
func (h *Handler) setJWTCookie(w http.ResponseWriter, token string) {
	const cookieTTL = 7 * 24 * 60 * 60 // 7 days in seconds
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.EnableTLS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieTTL,
	})
}

// sendJSONError sends a JSON error response.
func (h *Handler) sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
