package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// allowedExtensions lists permitted file extensions for static serving.
var allowedExtensions = map[string]bool{
	".html": true,
	".css":  true,
	".js":   true,
	".png":  true,
	".jpg":  true,
	".svg":  true,
	".webp": true,
	".map":  true,
	".txt":  true,
	".ico":  true,
}

// AddStaticHandlers registers handlers for static files and favicon.
func AddStaticHandlers(mux *http.ServeMux) {
	// Redirect favicon.ico to static file
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.ico", http.StatusMovedPermanently)
	})

	// Serve static files with restrictions
	staticFS := http.FileServer(http.Dir("./static"))
	staticHandler := http.StripPrefix("/static/", noDirListing(staticFS))
	mux.Handle("/static/", staticHandler)
}

// noDirListing disables directory listing and enforces extension filtering.
func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Compute file path
		path := filepath.Join("./static", strings.TrimPrefix(r.URL.Path, "/static"))

		// Check file existence
		info, err := os.Stat(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Block directories
		if info.IsDir() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Restrict to allowed extensions
		ext := strings.ToLower(filepath.Ext(path))
		if !allowedExtensions[ext] {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Serve the file
		next.ServeHTTP(w, r)
	})
}
