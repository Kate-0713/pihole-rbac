// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "net/http"

// NewMux returns the router. Method-and-path patterns are the stdlib mux's, so GET also matches HEAD and other methods get a 405.
func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", Healthz)
	mux.HandleFunc("GET /api/v1/about", GetAbout)
	return mux
}
