// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"
)

// Routes come from api/openapi.yaml through the generated gen.HandlerWithOptions; see New.

// publicRoutes are the operations that work without a session: those with `security: []` in api/openapi.yaml.
// State-changing requests among them still need the CSRF and Origin checks.
var publicRoutes = map[string]bool{
	"GET /healthz":            true,
	"GET /api/v1/about":       true,
	"GET /api/v1/auth/csrf":   true,
	"POST /api/v1/auth/login": true,
}

// apiNotFound answers /api/ paths no route matched, in the error envelope: 405 if the path exists with another
// method, otherwise 404.
func (s *Server) apiNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var allowed []string
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		probe := r.Clone(r.Context())
		probe.Method = m
		if _, pattern := s.mux.Handler(probe); pattern != "" && pattern != "/api/" {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "That method isn't allowed here.")
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "No such API endpoint.")
}
