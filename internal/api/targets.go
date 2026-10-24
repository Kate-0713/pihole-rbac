// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// The /targets/{target}/... endpoints act on one Pi-hole. Each handler validates its input, calls resolveTarget
// (which parses the target, checks the permission and finds the instance), then does its Pi-hole calls in one
// s.call, which goes through the pool's backoff and health tracking. Writes are audited after the call with
// auditPihole.

// instanceRef is the instance a target request acts on.
type instanceRef struct {
	target rbac.Target
	id     int64
	name   string
}

// piholeFailure is a Pi-hole call that failed for one instance: the instance can't be used, or its Pi-hole was
// unreachable, refused the app password, answered unexpectedly or refused the request's content. responseError
// answers it with piholeFailed. Results, when set, are a write's results for every instance, sent in
// details.results (see finishWrite).
type piholeFailure struct {
	Instance string
	Err      error
	Results  any
}

func (e *piholeFailure) Error() string {
	return "instance " + strconv.Quote(e.Instance) + ": " + e.Err.Error()
}
func (e *piholeFailure) Unwrap() error { return e.Err }

func invalid(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func targetNotFound(t rbac.Target) *rbac.Error {
	return &rbac.Error{
		Code: rbac.CodeNotFound, Message: fmt.Sprintf("%s isn't an enabled instance.", t),
		Details: map[string]any{"target": t.String()},
	}
}

// authorizeAny returns a forbidden error unless the session holds at least one permission on target t.
func (s *Server) authorizeAny(ctx context.Context, t rbac.Target) error {
	set, err := s.permissions(ctx)
	if err != nil {
		return err
	}
	if !set.CanAny(t) {
		return rbac.ForbiddenAny(t)
	}
	return nil
}

// resolveTarget parses a {target}, checks that the session holds p on it (any permission when p is ""), and finds
// the enabled instance it names. Only instances are targets so far; a mirrored group is a 404 until group fan-out
// exists. A target the user holds nothing on is a 403 whether or not it exists, so the answer reveals nothing.
func (s *Server) resolveTarget(ctx context.Context, raw string, p rbac.Permission) (instanceRef, error) {
	if s.Instances == nil {
		return instanceRef{}, errNoInstances
	}
	t, err := rbac.ParseTarget(raw)
	if err != nil {
		return instanceRef{}, invalid("target", `The target must be "i-<id>" for an instance or "g-<id>" for a mirrored group.`)
	}
	if t.Kind != rbac.TargetInstance {
		return instanceRef{}, &rbac.Error{
			Code: rbac.CodeNotFound, Message: "Mirrored groups can't be used as targets yet.",
			Details: map[string]any{"target": t.String()},
		}
	}
	if p == "" {
		err = s.authorizeAny(ctx, t)
	} else {
		err = s.authorize(ctx, p, t)
	}
	if err != nil {
		return instanceRef{}, err
	}
	name, ok := s.Instances.Pool.Name(t.ID)
	if !ok {
		return instanceRef{}, targetNotFound(t)
	}
	return instanceRef{target: t, id: t.ID, name: name}, nil
}

// call runs fn with the instance's Pi-hole client through the pool. fn may return an *rbac.Error of its own (an
// entry that doesn't exist, a group the Pi-hole doesn't have), which passes through; a Pi-hole or instance failure
// becomes a *piholeFailure. An instance disabled since resolveTarget is a 404.
func (s *Server) call(ctx context.Context, ref instanceRef, fn func(context.Context, *piholeapi.Client) error) error {
	err := s.Instances.Pool.Do(ctx, ref.id, fn)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, instances.ErrNotFound):
		return targetNotFound(ref.target)
	case ctx.Err() != nil:
		return err
	}
	if _, ok := rbac.AsError(err); ok {
		return err
	}
	if instances.Kind(err) == "" {
		return err
	}
	return &piholeFailure{Instance: ref.name, Err: err}
}

// piholeFailed answers a *piholeFailure with the error envelope (see describeFailure), adding the write's results
// when it has them.
func (s *Server) piholeFailed(w http.ResponseWriter, r *http.Request, pf *piholeFailure) {
	f := describeFailure(pf)
	if f.internal {
		s.Logger.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", pf)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return
	}
	s.logFailure(r.Pattern, pf)
	details := map[string]any{"instance": pf.Instance}
	if f.piholeMessage != "" {
		details["pihole_message"] = f.piholeMessage
	}
	if pf.Results != nil {
		details["results"] = pf.Results
	}
	body := errorBody(f.code, f.message)
	body.Error.Details = &details
	writeJSON(w, f.status, body)
}

// auditPihole records a Pi-hole write after the call, with its result. Handlers call it only when the write was
// attempted: a request refused before that (bad input, an entry that doesn't exist, an instance in its backoff)
// changed nothing. The Pi-hole has already acted, so the row is written even if the client has gone away, and a failure to
// write it is logged rather than reported to the client as a failure of the change.
func (s *Server) auditPihole(ctx context.Context, ref instanceRef, action string, err error, detail map[string]any) {
	ri := info(ctx)
	if detail == nil {
		detail = map[string]any{}
	}
	if err != nil {
		if code := instances.Kind(err); code != "" {
			detail["error_code"] = code
		}
	}
	e := audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: action, Target: ref.target.String(),
		InstanceID: ref.id, InstanceName: ref.name, Err: err, Detail: detail, IP: ri.ip,
	}
	if aerr := s.Audit.Record(context.WithoutCancel(ctx), s.Store, e); aerr != nil {
		s.Logger.Error("recording a pi-hole write", "action", action, "instance", ref.name, "err", aerr)
	}
}

// Input limits. Pi-hole checks domains and regexes itself; these only keep junk out of its API and the audit log.
const (
	maxExactDomainBytes = 255
	maxRegexBytes       = 1024
	maxCommentRunes     = 500
	maxClientIDBytes    = 255
	maxFilterRunes      = 255
	maxGroupIDs         = 1000
	maxBlockingTimer    = 86400 // seconds
)

// checkText refuses invalid UTF-8 and control characters (newlines included) and anything over max runes.
func checkText(field, s string, max int) error {
	if !utf8.ValidString(s) {
		return invalid(field, "The %s isn't valid text.", field)
	}
	if utf8.RuneCountInString(s) > max {
		return invalid(field, "The %s is longer than %d characters.", field, max)
	}
	if i := slices.IndexFunc([]rune(s), unicode.IsControl); i >= 0 {
		return invalid(field, "The %s can't contain control characters or line breaks.", field)
	}
	return nil
}

// checkDomainKey checks the fields that name a list entry. The domain is used exactly as given, since it has to
// match the entry.
func checkDomainKey(domain, listType, kind string) error {
	if !piholeapi.ValidDomainType(listType) {
		return invalid("type", `The type must be "allow" or "deny".`)
	}
	if !piholeapi.ValidDomainKind(kind) {
		return invalid("kind", `The kind must be "exact" or "regex".`)
	}
	if domain == "" {
		return invalid("domain", "The domain can't be empty.")
	}
	max := maxExactDomainBytes
	if kind == "regex" {
		max = maxRegexBytes
	}
	if len(domain) > max {
		return invalid("domain", "The %s is longer than %d bytes.", map[string]string{"exact": "domain", "regex": "regex"}[kind], max)
	}
	return checkText("domain", domain, max)
}

// checkGroupIDs checks the shape of a list of Pi-hole group IDs from a request; whether they exist on the Pi-hole
// is checked against its groups with resolveGroups.
func checkGroupIDs(ids []int) error {
	if len(ids) > maxGroupIDs {
		return invalid("groups", "At most %d groups can be given.", maxGroupIDs)
	}
	for _, id := range ids {
		if id < 0 {
			return invalid("groups", "Group IDs can't be negative.")
		}
	}
	return nil
}

// resolveGroups returns ids sorted and without duplicates, or a validation error naming the ones the Pi-hole doesn't
// have.
func resolveGroups(ids []int, groups []piholeapi.Group) ([]int, error) {
	out := slices.Clone(ids)
	slices.Sort(out)
	out = slices.Compact(out)
	var unknown []int
	for _, id := range out {
		if !slices.ContainsFunc(groups, func(g piholeapi.Group) bool { return g.ID == id }) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		e := invalid("groups", "The Pi-hole has no group with ID %s.", joinInts(unknown))
		e.Details["unknown_groups"] = unknown
		return nil, e
	}
	if out == nil {
		out = []int{}
	}
	return out, nil
}

// groupNames names group IDs for the audit log, falling back to #<id> for a group the Pi-hole no longer lists.
func groupNames(ids []int, groups []piholeapi.Group) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.ID == id })
		if i >= 0 {
			out = append(out, groups[i].Name)
		} else {
			out = append(out, "#"+strconv.Itoa(id))
		}
	}
	return out
}

func joinInts(ns []int) string {
	s := ""
	for i, n := range ns {
		if i > 0 {
			s += ", "
		}
		s += strconv.Itoa(n)
	}
	return s
}

// sortedIDs returns a sorted copy of ids, never nil.
func sortedIDs(ids []int) []int {
	out := append([]int{}, ids...)
	slices.Sort(out)
	return out
}

func nonNilInts(ids []int) []int {
	if ids == nil {
		return []int{}
	}
	return ids
}
