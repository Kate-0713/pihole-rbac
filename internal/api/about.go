// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
)

// GetAbout is unauthenticated and stays available before first-run setup, so every page can show the AGPL-3.0
// section 13 source link. It must never include the version.
func (s *Server) GetAbout(context.Context, gen.GetAboutRequestObject) (gen.GetAboutResponseObject, error) {
	return gen.GetAbout200JSONResponse{SourceUrl: buildinfo.Source, License: buildinfo.License}, nil
}
