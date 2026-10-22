// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
)

// About is the response of GET /api/v1/about (schema About in api/openapi.yaml). Hand-written until the oapi-codegen types are wired up.
type About struct {
	SourceURL string `json:"source_url"`
	License   string `json:"license"`
}

// GetAbout is unauthenticated and stays available before first-run setup, so every page can show the AGPL-3.0 section 13 source link. It must never include the version.
func GetAbout(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_ = json.NewEncoder(w).Encode(About{SourceURL: buildinfo.Source, License: buildinfo.License})
}
