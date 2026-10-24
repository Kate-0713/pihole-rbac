// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// permissions returns what the request's session may do. It is resolved from the session's role IDs and the current
// groups the first time it is asked for and kept for the rest of the request only, so a change to a role or a group
// applies to the very next request.
func (s *Server) permissions(ctx context.Context) (*rbac.Set, error) {
	ri := info(ctx)
	if ri.perms != nil {
		return ri.perms, nil
	}
	if ri.sess == nil {
		return rbac.NewSet(nil, nil), nil // no session, no permissions
	}
	set, err := rbac.Resolve(ctx, s.Store.Read(), ri.sess.RoleIDs)
	if err != nil {
		return nil, err
	}
	ri.perms = set
	return set, nil
}

// requireGlobal returns a forbidden error unless the session holds at least one of the global permissions ps.
func (s *Server) requireGlobal(ctx context.Context, ps ...rbac.Permission) error {
	set, err := s.permissions(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if set.CanGlobal(p) {
			return nil
		}
	}
	if len(ps) == 1 {
		return rbac.Forbidden(ps[0])
	}
	return rbac.ForbiddenEither(ps...)
}

// authorize returns a forbidden error unless the session holds p on target t. Handlers call it as soon as they have
// parsed the target, before they read or write anything for it.
func (s *Server) authorize(ctx context.Context, p rbac.Permission, t rbac.Target) error {
	set, err := s.permissions(ctx)
	if err != nil {
		return err
	}
	if !set.Can(p, t) {
		return rbac.ForbiddenOn(p, t)
	}
	return nil
}

// sessionPermissions is the permissions object of the session response, for a session that may not be the
// request's own (login and setup respond before the request has one).
func (s *Server) sessionPermissions(ctx context.Context, sess *auth.Session) (gen.Permissions, error) {
	set, err := rbac.Resolve(ctx, s.Store.Read(), sess.RoleIDs)
	if err != nil {
		return gen.Permissions{}, err
	}
	out := gen.Permissions{Global: []string{}, Targets: map[string][]string{}}
	for _, p := range set.Global() {
		out.Global = append(out.Global, string(p))
	}
	for t, ps := range set.ByTarget() {
		names := make([]string, len(ps))
		for i, p := range ps {
			names[i] = string(p)
		}
		out.Targets[t.String()] = names
	}
	return out, nil
}

// statusForCode maps a refusal from the rbac package to its HTTP status.
func statusForCode(c rbac.Code) int {
	switch c {
	case rbac.CodeValidation:
		return http.StatusBadRequest
	case rbac.CodeForbidden:
		return http.StatusForbidden
	case rbac.CodeNotFound:
		return http.StatusNotFound
	case rbac.CodeConflict, rbac.CodeInvariant, rbac.CodeConfirmation:
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// refuse answers a refusal from the rbac package, whether it came from the gate, authorize or a service call. A
// refused state-changing request is audited as permission_denied (the rbac service does the same for its own
// refusals, in its transaction); a refused read is only logged, to keep the audit log useful.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, e *rbac.Error) {
	ri := info(r.Context())
	if e.Code == rbac.CodeForbidden && ri.sess != nil {
		if isSafeMethod(r.Method) {
			s.Logger.Info("permission denied", "user", ri.sess.Username, "request", r.Pattern, "details", e.Details)
		} else {
			detail := map[string]any{"attempted": r.Pattern}
			for k, v := range e.Details {
				detail[k] = v
			}
			target, _ := e.Details["target"].(string)
			entry := audit.Entry{
				UserID: ri.sess.UserID, Username: ri.sess.Username, Action: audit.ActionPermissionDenied,
				Target: target, Err: e, Detail: detail, IP: ri.ip,
			}
			if err := s.Audit.Record(r.Context(), s.Store, entry); err != nil {
				s.Logger.Error("recording permission_denied", "err", err)
			}
		}
	}
	body := errorBody(string(e.Code), e.Message)
	if len(e.Details) > 0 {
		body.Error.Details = &e.Details
	}
	writeJSON(w, statusForCode(e.Code), body)
}
