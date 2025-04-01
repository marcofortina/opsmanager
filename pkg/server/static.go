package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"opsmanager/pkg/logger"
)

// StaticHandler serves static files with restrictions
type StaticHandler struct {
	dir        string
	extensions map[string]struct{}
	log        *logger.LogManager
}

// StaticConfig holds configuration for StaticHandler
type StaticConfig struct {
	Dir        string             // Directory for static files
	Extensions []string           // Allowed file extensions
	Logger     *logger.LogManager // Optional logger
}

// Default allowed extensions
var defaultExtensions = []string{
	".html", ".css", ".js", ".png", ".jpg", ".svg", ".webp", ".map", ".txt", ".ico",
}

// NewStaticHandler creates a new StaticHandler instance
func NewStaticHandler(cfg StaticConfig) *StaticHandler {
	if cfg.Dir == "" {
		cfg.Dir = "./static"
	}
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = defaultExtensions
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.Default()
	}

	extSet := make(map[string]struct{}, len(cfg.Extensions))
	for _, ext := range cfg.Extensions {
		extSet[strings.ToLower(ext)] = struct{}{}
	}

	return &StaticHandler{
		dir:        cfg.Dir,
		extensions: extSet,
		log:        cfg.Logger,
	}
}

// AddStaticHandlers registers static file handlers
func (sh *StaticHandler) AddStaticHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.ico", http.StatusMovedPermanently)
	})

	staticFS := http.FileServer(http.Dir(sh.dir))
	handler := http.StripPrefix("/static/", sh.noDirListing(staticFS))
	mux.Handle("/static/", handler)
}

// noDirListing disables directory listing and enforces restrictions
func (sh *StaticHandler) noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the relative path (already stripped of /static/ by StripPrefix)
		relativePath := r.URL.Path

		// Build the full path and clean it
		path := filepath.Join(sh.dir, filepath.Clean(relativePath))

		// Verify that the path is within sh.dir
		rel, err := filepath.Rel(sh.dir, path)
		if err != nil || strings.HasPrefix(rel, "..") || strings.HasPrefix(rel, "/") {
			sh.log.Warnf("Path traversal attempt: %s", r.URL.Path)
			sh.sendError(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check if the file exists and is not a directory
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				sh.sendError(w, "Not Found", http.StatusNotFound)
			} else {
				sh.log.Errorf("Failed to stat %s: %v", path, err)
				sh.sendError(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		if info.IsDir() {
			sh.sendError(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check the file extension
		ext := strings.ToLower(filepath.Ext(path))
		if _, ok := sh.extensions[ext]; !ok {
			sh.log.Warnf("Forbidden extension %s for %s", ext, r.URL.Path)
			sh.sendError(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Serve the file
		sh.log.Debugf("Serving static file: %s", path)
		next.ServeHTTP(w, r)
	})
}

// sendError sends an HTTP error response
func (sh *StaticHandler) sendError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}
