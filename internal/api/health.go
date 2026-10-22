// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
)

// Healthz is unauthenticated and returns only "ok", for Docker health checks and the LXC updater. It must never
// reveal anything about the install.
func (s *Server) Healthz(context.Context, gen.HealthzRequestObject) (gen.HealthzResponseObject, error) {
	return gen.Healthz200TextResponse("ok"), nil
}

// writeJSON writes v as a JSON response, for errors raised before a generated handler runs.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
