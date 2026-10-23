// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Routes come from api/openapi.yaml through the generated gen.HandlerWithOptions; see New.

// Access values for routePermission besides a permission name.
const (
	accessPublic  = "public"  // no session needed: `security: []` in the spec, no x-permission
	accessSession = "session" // any session: x-permission: session
	targetPrefix  = "target:" // the handler checks the permission against a target: x-permission: target:<permission>
)

// routePermission says what each operation needs, keyed by the mux pattern (r.Pattern). It repeats the x-permission
// extensions of api/openapi.yaml, and TestRoutePermissionsMatchSpec checks the two against each other in both
// directions, so an operation can't ship without a declared permission. A value is accessPublic, accessSession, a
// global permission (checked by the gate) or "target:<permission>" (checked by the handler with authorize, once it has
// parsed the target). Public operations still need the CSRF and Origin checks when they change state.
var routePermission = map[string]string{
	"GET /healthz":             accessPublic,
	"GET /api/v1/about":        accessPublic,
	"GET /api/v1/auth/csrf":    accessPublic,
	"POST /api/v1/auth/login":  accessPublic,
	"GET /api/v1/setup/status": accessPublic,
	"POST /api/v1/setup":       accessPublic,

	"POST /api/v1/auth/logout": accessSession,
	"GET /api/v1/auth/session": accessSession,

	"GET /api/v1/targets": accessSession,

	"GET /api/v1/system/secrets": string(rbac.ConfigReload),
	"POST /api/v1/system/reload": string(rbac.ConfigReload),

	"GET /api/v1/instances":               string(rbac.InstancesManage),
	"POST /api/v1/instances":              string(rbac.InstancesManage),
	"GET /api/v1/instances/{id}":          string(rbac.InstancesManage),
	"PUT /api/v1/instances/{id}":          string(rbac.InstancesManage),
	"DELETE /api/v1/instances/{id}":       string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/test":    string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/enable":  string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/disable": string(rbac.InstancesManage),
}

// parseAccess splits a routePermission value. ok is false for a value that isn't valid: unknown permission, a
// target-scoped one where a global one is needed, or the other way round.
func parseAccess(v string) (kind, permission string, ok bool) {
	switch {
	case v == accessPublic || v == accessSession:
		return v, "", true
	case strings.HasPrefix(v, targetPrefix):
		p := rbac.Permission(strings.TrimPrefix(v, targetPrefix))
		return "target", string(p), p.Known() && p.Class() != rbac.ClassGlobal
	}
	p := rbac.Permission(v)
	return "global", v, p.Known() && p.Class() == rbac.ClassGlobal
}

// setupRoutes are the operations that work before first-run setup is complete. Every other API route answers 503
// setup_required until then. The CSRF endpoint is among them because completing setup is a POST.
var setupRoutes = map[string]bool{
	"GET /healthz":             true,
	"GET /api/v1/about":        true,
	"GET /api/v1/auth/csrf":    true,
	"GET /api/v1/setup/status": true,
	"POST /api/v1/setup":       true,
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
