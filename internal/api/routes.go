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
	// accessTargetAny: the handler checks that the session holds at least one permission on the target, for reads every
	// user of a target needs (its dashboard, its Pi-hole group names).
	accessTargetAny = targetPrefix + "any"
)

// routePermission says what each operation needs, keyed by the mux pattern (r.Pattern). It repeats the x-permission
// extensions of api/openapi.yaml, and TestRoutePermissionsMatchSpec checks the two against each other in both
// directions, so an operation can't ship without a declared permission. A value is accessPublic, accessSession, a
// global permission (checked by the gate), "target:<permission>" (checked by the handler with authorize, once it has
// parsed the target) or "target:any" (checked by the handler with authorizeAny). Public operations still need the CSRF
// and Origin checks when they change state.
var routePermission = map[string]string{
	"GET /healthz":             accessPublic,
	"GET /api/v1/about":        accessPublic,
	"GET /api/v1/auth/csrf":    accessPublic,
	"POST /api/v1/auth/login":  accessPublic,
	"GET /api/v1/setup/status": accessPublic,
	"POST /api/v1/setup":       accessPublic,

	"POST /api/v1/auth/logout":   accessSession,
	"GET /api/v1/auth/session":   accessSession,
	"POST /api/v1/auth/password": accessSession,

	"GET /api/v1/targets": accessSession,

	"GET /api/v1/system/secrets": string(rbac.ConfigReload),
	"POST /api/v1/system/reload": string(rbac.ConfigReload),

	"GET /api/v1/instances":                         string(rbac.InstancesManage),
	"POST /api/v1/instances":                        string(rbac.InstancesManage),
	"GET /api/v1/instances/{id}":                    string(rbac.InstancesManage),
	"PUT /api/v1/instances/{id}":                    string(rbac.InstancesManage),
	"DELETE /api/v1/instances/{id}":                 string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/test":              string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/enable":            string(rbac.InstancesManage),
	"POST /api/v1/instances/{id}/disable":           string(rbac.InstancesManage),
	"PUT /api/v1/instances/{id}/password":           string(rbac.InstancesManage),
	"GET /api/v1/instance-groups":                   string(rbac.InstancesManage),
	"POST /api/v1/instance-groups":                  string(rbac.InstancesManage),
	"GET /api/v1/instance-groups/{id}":              string(rbac.InstancesManage),
	"PUT /api/v1/instance-groups/{id}":              string(rbac.InstancesManage),
	"DELETE /api/v1/instance-groups/{id}":           string(rbac.InstancesManage),
	"GET /api/v1/instance-groups/{id}/drift":        targetPrefix + string(rbac.DriftView),
	"POST /api/v1/instance-groups/{id}/drift/check": targetPrefix + string(rbac.DriftView),
	"POST /api/v1/instance-groups/{id}/reconcile":   targetPrefix + string(rbac.DriftReconcile),

	"GET /api/v1/roles":             anyOf(rbac.RolesManage, rbac.UsersManage),
	"POST /api/v1/roles":            string(rbac.RolesManage),
	"GET /api/v1/roles/catalogue":   string(rbac.RolesManage),
	"GET /api/v1/roles/{id}":        anyOf(rbac.RolesManage, rbac.UsersManage),
	"PUT /api/v1/roles/{id}":        string(rbac.RolesManage),
	"DELETE /api/v1/roles/{id}":     string(rbac.RolesManage),
	"PUT /api/v1/roles/{id}/grants": string(rbac.RolesManage),

	"GET /api/v1/roles/{id}/ldap-groups":                 string(rbac.RolesManage),
	"POST /api/v1/roles/{id}/ldap-groups":                string(rbac.RolesManage),
	"DELETE /api/v1/roles/{id}/ldap-groups/{mapping_id}": string(rbac.RolesManage),
	"POST /api/v1/ldap/test-user":                        string(rbac.RolesManage),
	"POST /api/v1/ldap/check-group":                      string(rbac.RolesManage),

	"GET /api/v1/notifications/channels":             string(rbac.NotifyManage),
	"POST /api/v1/notifications/channels":            string(rbac.NotifyManage),
	"GET /api/v1/notifications/channels/{id}":        string(rbac.NotifyManage),
	"PUT /api/v1/notifications/channels/{id}":        string(rbac.NotifyManage),
	"DELETE /api/v1/notifications/channels/{id}":     string(rbac.NotifyManage),
	"PUT /api/v1/notifications/channels/{id}/secret": string(rbac.NotifyManage),
	"POST /api/v1/notifications/channels/{id}/test":  string(rbac.NotifyManage),
	"GET /api/v1/notifications/events":               string(rbac.NotifyManage),
	"GET /api/v1/notifications/protected-groups":     string(rbac.NotifyManage),
	"PUT /api/v1/notifications/protected-groups":     string(rbac.NotifyManage),

	"GET /api/v1/audit":        string(rbac.AuditView),
	"GET /api/v1/audit/export": string(rbac.AuditView),

	"GET /api/v1/sessions":                accessSession,
	"DELETE /api/v1/sessions/{public_id}": accessSession,

	"GET /api/v1/client-reset/rules": string(rbac.SettingsManage),
	"PUT /api/v1/client-reset/rules": string(rbac.SettingsManage),
	"GET /api/v1/client-reset/runs":  string(rbac.SettingsManage),

	"GET /api/v1/settings/general": string(rbac.SettingsManage),
	"PUT /api/v1/settings/general": string(rbac.SettingsManage),
	"GET /api/v1/settings/auth":    string(rbac.SettingsManage),
	"PUT /api/v1/settings/auth":    string(rbac.SettingsManage),
	"GET /api/v1/settings/ldap":    string(rbac.SettingsManage),
	"PUT /api/v1/settings/ldap":    string(rbac.SettingsManage),

	"GET /api/v1/users":                string(rbac.UsersManage),
	"POST /api/v1/users":               string(rbac.UsersManage),
	"GET /api/v1/users/{id}":           string(rbac.UsersManage),
	"DELETE /api/v1/users/{id}":        string(rbac.UsersManage),
	"POST /api/v1/users/{id}/enable":   string(rbac.UsersManage),
	"POST /api/v1/users/{id}/disable":  string(rbac.UsersManage),
	"POST /api/v1/users/{id}/password": string(rbac.UsersManage),
	"PUT /api/v1/users/{id}/roles":     string(rbac.UsersManage),

	"GET /api/v1/targets/{target}/summary":      accessTargetAny,
	"GET /api/v1/targets/{target}/blocking":     accessTargetAny,
	"PUT /api/v1/targets/{target}/blocking":     targetPrefix + string(rbac.BlockingToggle),
	"POST /api/v1/targets/{target}/dns/restart": targetPrefix + string(rbac.DNSRestart),
	"GET /api/v1/targets/{target}/domains":      targetPrefix + string(rbac.DomainsView),
	"POST /api/v1/targets/{target}/domains":     targetPrefix + string(rbac.DomainsEdit),
	"PATCH /api/v1/targets/{target}/domains":    targetPrefix + string(rbac.DomainsEdit),
	"DELETE /api/v1/targets/{target}/domains":   targetPrefix + string(rbac.DomainsEdit),
	"GET /api/v1/targets/{target}/clients":      targetPrefix + string(rbac.ClientsView),
	"PATCH /api/v1/targets/{target}/clients":    targetPrefix + string(rbac.ClientsEdit),
	"GET /api/v1/targets/{target}/groups":       accessTargetAny,
	"GET /api/v1/targets/{target}/queries":      targetPrefix + string(rbac.QueryLogView),

	"GET /api/v1/targets/{target}/client-reset/preview": targetPrefix + string(rbac.ClientResetRun),
	"POST /api/v1/targets/{target}/client-reset/run":    targetPrefix + string(rbac.ClientResetRun),
	"GET /api/v1/targets/{target}/client-reset/runs":    targetPrefix + string(rbac.ClientResetRun),
}

// longRoutes may take longer than the server's write timeout: a client reset reads, and for a run changes, every
// client on every instance of its target. The gate gives them their own write deadline, a little over a run's limit.
var longRoutes = map[string]bool{
	"GET /api/v1/targets/{target}/client-reset/preview": true,
	"POST /api/v1/targets/{target}/client-reset/run":    true,
}

// anyOf is the routePermission value for an operation that any one of several global permissions allows, written
// as in the spec's x-permission: "roles.manage|users.manage".
func anyOf(ps ...rbac.Permission) string {
	names := make([]string, len(ps))
	for i, p := range ps {
		names[i] = string(p)
	}
	return strings.Join(names, "|")
}

// globalPermissions splits a "global" access value into its permissions: one, or several separated by "|".
func globalPermissions(v string) []rbac.Permission {
	parts := strings.Split(v, "|")
	out := make([]rbac.Permission, len(parts))
	for i, p := range parts {
		out[i] = rbac.Permission(p)
	}
	return out
}

// parseAccess splits a routePermission value. ok is false for a value that isn't valid: unknown permission, a
// target-scoped one where a global one is needed, or the other way round. A global value can name several
// permissions separated by "|", any one of which is enough; each must be a known global permission, named once.
func parseAccess(v string) (kind, permission string, ok bool) {
	switch {
	case v == accessPublic || v == accessSession:
		return v, "", true
	case v == accessTargetAny:
		return "target", "", true
	case strings.HasPrefix(v, targetPrefix):
		p := rbac.Permission(strings.TrimPrefix(v, targetPrefix))
		return "target", string(p), p.Known() && p.Class() != rbac.ClassGlobal
	}
	ps := globalPermissions(v)
	seen := map[rbac.Permission]bool{}
	for _, p := range ps {
		if !p.Known() || p.Class() != rbac.ClassGlobal || seen[p] {
			return "global", v, false
		}
		seen[p] = true
	}
	return "global", v, true
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
