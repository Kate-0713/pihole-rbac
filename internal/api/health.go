// Package api holds the HTTP handlers and routing.
package api

import "net/http"

// Healthz is unauthenticated and returns only "ok", for Docker health checks
// and the LXC updater. It must never reveal anything about the install.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
}

// NewMux returns the router. Method-and-path patterns are the stdlib mux's
// (Go 1.22+), so GET also matches HEAD and anything else gets a 405.
func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", Healthz)
	return mux
}
