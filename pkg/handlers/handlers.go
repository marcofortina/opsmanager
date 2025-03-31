package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"time"

	"opsmanager/pkg/auth"
	"opsmanager/pkg/config"
	"opsmanager/pkg/etcd"
	"opsmanager/pkg/logger"
)

// Handler manages HTTP request handlers
type Handler struct {
	templates map[string]*template.Template
	jwtMgr    *auth.JWTManager
	csrfMgr   *auth.CSRFManager
	loginMgr  *auth.LoginManager
	totpMgr   *auth.TOTPManager
	etcd      *etcd.Client
	log       *logger.Logger
	cfg       *config.Config
	opTimeout time.Duration
}

// HandlerConfig holds configuration for Handler
type HandlerConfig struct {
	TemplateDir string
	JWTMgr      *auth.JWTManager
	CSRFMgr     *auth.CSRFManager
	LoginMgr    *auth.LoginManager
	TotpMgr     *auth.TOTPManager
	Etcd        *etcd.Client
	Logger      *logger.Logger
	Config      *config.Config
	OpTimeout   time.Duration
}

// New initializes a new Handler instance
func New(cfg HandlerConfig) (*Handler, error) {
	if cfg.OpTimeout == 0 {
		cfg.OpTimeout = 2 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}
	if cfg.TotpMgr == nil {
		totpCfg := &auth.TOTPConfig{
			Seed:       cfg.Config.TwoFactor.Secret,
			Interval:   auth.DefaultTOTPInterval,
			CodeLength: auth.DefaultTOTPCodeLength,
			Logger:     cfg.Logger,
		}
		var err error
		cfg.TotpMgr, err = auth.NewTOTPManager(totpCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize TOTP manager: %v", err)
		}
	}

	tmpls := make(map[string]*template.Template)
	for _, name := range []string{"login.html", "dashboard.html", "config.html"} {
		tmpl, err := template.ParseFiles(filepath.Join(cfg.TemplateDir, name))
		if err != nil {
			cfg.Logger.Errorf("Failed to parse template %s: %v", name, err)
			return nil, fmt.Errorf("failed to parse template %s: %v", name, err)
		}
		tmpls[name] = tmpl
	}

	return &Handler{
		templates: tmpls,
		jwtMgr:    cfg.JWTMgr,
		csrfMgr:   cfg.CSRFMgr,
		loginMgr:  cfg.LoginMgr,
		totpMgr:   cfg.TotpMgr, // Aggiunto
		etcd:      cfg.Etcd,
		log:       cfg.Logger,
		cfg:       cfg.Config,
		opTimeout: cfg.OpTimeout,
	}, nil
}

// Login handles login page and authentication
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.handleLoginPost(w, r)
		return
	}
	h.handleLoginGet(w, r)
}

// handleLoginGet renders the login page
func (h *Handler) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if _, err := h.jwtMgr.VerifyToken(cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	csrfToken, err := h.csrfMgr.GenerateToken()
	if err != nil {
		h.log.Errorf("Failed to generate CSRF token: %v", err)
		h.sendError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()
	if err := h.etcd.StoreSession(ctx, "csrf:"+csrfToken, csrfToken, etcd.SessionTTL5Minutes); err != nil {
		h.log.Errorf("Failed to store CSRF token: %v", err)
		h.sendError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	h.renderTemplate(w, "login.html", map[string]string{"CSRFToken": csrfToken})
}

// handleLoginPost processes login form submission
func (h *Handler) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := r.ParseForm(); err != nil {
		h.sendJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	csrfToken := r.FormValue("csrf_token")
	if username == "" || password == "" {
		h.sendJSONError(w, "Missing username or password", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()
	storedToken, err := h.etcd.GetSession(ctx, "csrf:"+csrfToken)
	if err != nil || storedToken != csrfToken {
		h.log.Warnf("Invalid CSRF token for %s", username)
		h.sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if !h.loginMgr.VerifyCredentials(username, password) {
		h.sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := h.etcd.DeleteSession(ctx, "csrf:"+csrfToken); err != nil {
		h.log.Warnf("Failed to delete CSRF token for %s: %v", username, err)
	}

	if !h.cfg.TwoFactor.Enabled {
		h.completeLogin(w, username)
		return
	}
	h.initiate2FA(w, ctx, username)
}

// completeLogin generates a long-term JWT
func (h *Handler) completeLogin(w http.ResponseWriter, username string) {
	const tokenTTL = 7 * 24 * 60 * 60 * time.Second
	token, err := h.jwtMgr.GenerateToken(username, tokenTTL)
	if err != nil {
		h.log.Errorf("Failed to generate JWT for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.opTimeout)
	defer cancel()
	if err := h.etcd.StoreSession(ctx, "session:"+username, token, etcd.SessionTTL7Days); err != nil {
		h.log.Errorf("Failed to store session for %s: %v", username, err)
		h.sendJSONError(w, "Session storage failed", http.StatusInternalServerError)
		return
	}

	h.setJWTCookie(w, token)
	h.log.Infof("User %s authenticated without 2FA", username)
	json.NewEncoder(w).Encode(map[string]interface{}{"redirect": "/dashboard"})
}

// initiate2FA starts the 2FA process
func (h *Handler) initiate2FA(w http.ResponseWriter, ctx context.Context, username string) {
	const tempTokenTTL = 5 * 60 * time.Second
	tempToken, err := h.jwtMgr.GenerateToken(username, tempTokenTTL)
	if err != nil {
		h.log.Errorf("Failed to generate temp token for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	csrfToken2FA, err := h.csrfMgr.GenerateToken()
	if err != nil {
		h.log.Errorf("Failed to generate 2FA CSRF token: %v", err)
		h.sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := h.etcd.StoreSession(ctx, "csrf_2fa:"+csrfToken2FA, csrfToken2FA, etcd.SessionTTL5Minutes); err != nil {
		h.log.Errorf("Failed to store 2FA CSRF token: %v", err)
		h.sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := h.etcd.StoreSession(ctx, "temp_auth:"+username, tempToken, etcd.SessionTTL5Minutes); err != nil {
		h.log.Errorf("Failed to store temp auth for %s: %v", username, err)
		h.sendJSONError(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	h.log.Infof("User %s awaiting 2FA", username)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"requires2FA":  true,
		"tempToken":    tempToken,
		"csrfToken2FA": csrfToken2FA,
	})
}

// Verify2FA processes 2FA verification
func (h *Handler) Verify2FA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

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

	if err := r.ParseForm(); err != nil {
		h.sendJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	tempToken := r.FormValue("tempToken")
	totpCode := r.FormValue("otp")
	csrfToken2FA := r.FormValue("csrf_token_2fa")
	if username == "" || totpCode == "" {
		h.sendJSONError(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	storedCSRF, err := h.etcd.GetSession(ctx, "csrf_2fa:"+csrfToken2FA)
	if err != nil || storedCSRF != csrfToken2FA {
		h.log.Warnf("Invalid 2FA CSRF token for %s", username)
		h.sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	claims, err := h.jwtMgr.VerifyToken(tempToken)
	if err != nil || claims["sub"] != username {
		h.log.Warnf("Invalid temp token for %s: %v", username, err)
		h.sendJSONError(w, "Session expired or invalid", http.StatusUnauthorized)
		return
	}
	storedToken, err := h.etcd.GetSession(ctx, "temp_auth:"+username)
	if err != nil || storedToken != tempToken {
		h.log.Warnf("Temp token mismatch for %s", username)
		h.sendJSONError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	if !h.totpMgr.VerifyTOTP(totpCode, time.Now()) { // Aggiornato
		h.log.Warnf("Invalid TOTP code for %s", username)
		h.sendJSONError(w, "Invalid 2FA code", http.StatusUnauthorized)
		return
	}

	h.completeLogin(w, username)

	if err := h.etcd.DeleteSession(ctx, "temp_auth:"+username); err != nil {
		h.log.Warnf("Failed to delete temp auth for %s: %v", username, err)
	}
	if err := h.etcd.DeleteSession(ctx, "csrf_2fa:"+csrfToken2FA); err != nil {
		h.log.Warnf("Failed to delete 2FA CSRF for %s: %v", username, err)
	}
}

// Logout clears the session and redirects
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.opTimeout)
	defer cancel()

	if cookie, err := r.Cookie("jwt_token"); err == nil {
		if claims, err := h.jwtMgr.VerifyToken(cookie.Value); err == nil {
			if username, ok := claims["sub"].(string); ok {
				if err := h.etcd.DeleteSession(ctx, "session:"+username); err != nil {
					h.log.Warnf("Failed to delete session for %s: %v", username, err)
				}
				h.log.Infof("User %s logged out", username)
			}
		}
	}

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

// Dashboard serves the dashboard page
func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Serving dashboard")
	h.renderTemplate(w, "dashboard.html", nil)
}

// Config serves the config page
func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	h.log.Debug("Serving config")
	h.renderTemplate(w, "config.html", nil)
}

// setJWTCookie sets a secure JWT cookie
func (h *Handler) setJWTCookie(w http.ResponseWriter, token string) {
	const cookieTTL = 7 * 24 * 60 * 60
	sameSite := http.SameSiteLaxMode
	if h.cfg.Server.EnableTLS {
		sameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.Server.EnableTLS,
		SameSite: sameSite,
		MaxAge:   cookieTTL,
	})
}

// renderTemplate renders a template with data
func (h *Handler) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := h.templates[name]
	if !ok {
		h.log.Errorf("Template %s not found", name)
		h.sendError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		h.log.Errorf("Failed to render %s: %v", name, err)
		h.sendError(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendError sends an HTML error response
func (h *Handler) sendError(w http.ResponseWriter, message string, code int) {
	http.Error(w, message, code)
}

// sendJSONError sends a JSON error response
func (h *Handler) sendJSONError(w http.ResponseWriter, message string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Close releases resources
func (h *Handler) Close() error {
	return h.etcd.Close()
}
