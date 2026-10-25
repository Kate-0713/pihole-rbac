// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Service keeps the rules and runs them.
type Service struct {
	Store     *store.Store
	Audit     *audit.Logger
	Instances *instances.Service
	// Protected returns the protected Pi-hole group names that apply to an instance, so a reset that puts a client in
	// one raises the same alert as a client update. Nil means no alerts.
	Protected func(ctx context.Context, instanceID int64) ([]string, error)
	Logger    *slog.Logger
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	mu sync.Mutex // one rules save at a time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

// Scope kinds: what a rule is set on.
const (
	ScopeInstance = "instance"
	ScopeGroup    = "group"
)

// RuleView is a rule as the API shows it.
type RuleView struct {
	Scope     string
	ScopeID   int64
	ScopeName string
	Prefix    string
	Match     Match
	Groups    []string
}

// Choice is an instance or mirrored group a rule can be set on.
type Choice struct {
	ID   int64
	Name string
}

// Settings is every rule and what rules can be set on. The choices come with them because someone with
// settings.manage may not be able to list instances otherwise.
type Settings struct {
	Rules     []RuleView
	Instances []Choice
	Groups    []Choice // mirrored groups only
}

// RuleInput is a rule as a request gives it.
type RuleInput struct {
	Scope  string
	ID     int64
	Prefix string
	Match  Match
	Groups []string
}

const (
	maxRules         = 500
	maxGroupsPerRule = 50
	maxNameRunes     = 255
)

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

// Rules returns every rule, instances first, then by name and prefix, with what rules can be set on.
func (s *Service) Rules(ctx context.Context) (Settings, error) {
	q := s.Store.Read()
	rows, err := q.ListClientResetRules(ctx)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{Rules: []RuleView{}, Instances: []Choice{}, Groups: []Choice{}}
	for _, r := range rows {
		v := RuleView{Scope: ScopeInstance, ScopeID: r.InstanceID.Int64, ScopeName: r.InstanceName,
			Prefix: r.CommentPrefix, Match: Match(r.GroupMatch)}
		if r.GroupID.Valid {
			v.Scope, v.ScopeID, v.ScopeName = ScopeGroup, r.GroupID.Int64, r.GroupName
		}
		if err := json.Unmarshal([]byte(r.TargetGroups), &v.Groups); err != nil {
			return Settings{}, fmt.Errorf("client reset rule %d: %w", r.ID, err)
		}
		out.Rules = append(out.Rules, v)
	}
	instances, err := q.ListInstances(ctx)
	if err != nil {
		return Settings{}, err
	}
	for _, i := range instances {
		out.Instances = append(out.Instances, Choice{ID: i.ID, Name: i.Name})
	}
	groups, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return Settings{}, err
	}
	for _, g := range groups {
		if g.Mode == string(rbac.Mirrored) {
			out.Groups = append(out.Groups, Choice{ID: g.ID, Name: g.Name})
		}
	}
	return out, nil
}

// checkName checks a comment prefix or a group name or prefix: 1 to 255 characters, no control characters. It isn't
// trimmed: a prefix is matched exactly.
func checkName(field, what, s string) error {
	if n := utf8.RuneCountInString(s); n == 0 || n > maxNameRunes || !utf8.ValidString(s) ||
		strings.IndexFunc(s, unicode.IsControl) >= 0 || strings.TrimSpace(s) == "" {
		return validation(field, "%s is 1-%d characters, with no control characters, and not only spaces.", what, maxNameRunes)
	}
	return nil
}

// checkInput validates the rules a request gives, and returns them cleaned: groups without duplicates, in the order
// given.
func checkInput(in []RuleInput) ([]RuleInput, error) {
	if len(in) > maxRules {
		return nil, validation("rules", "At most %d rules.", maxRules)
	}
	type key struct {
		scope  string
		id     int64
		prefix string
	}
	seen := map[key]bool{}
	out := make([]RuleInput, 0, len(in))
	for _, r := range in {
		if r.Scope != ScopeInstance && r.Scope != ScopeGroup {
			return nil, validation("scope", "A rule is set on an instance or a group.")
		}
		if err := checkName("comment_prefix", "A comment prefix", r.Prefix); err != nil {
			return nil, err
		}
		k := key{r.Scope, r.ID, r.Prefix}
		if seen[k] {
			return nil, validation("comment_prefix", "Each comment prefix is used once on an instance or group: %q is repeated.", r.Prefix)
		}
		seen[k] = true
		if r.Match != MatchNames && r.Match != MatchPrefixes {
			return nil, validation("group_match", "Groups are matched by names or by prefixes.")
		}
		if len(r.Groups) == 0 || len(r.Groups) > maxGroupsPerRule {
			return nil, validation("pihole_groups", "A rule names 1 to %d Pi-hole groups.", maxGroupsPerRule)
		}
		var groups []string
		for _, g := range r.Groups {
			if err := checkName("pihole_groups", "A Pi-hole group name or prefix", g); err != nil {
				return nil, err
			}
			if !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
		r.Groups = groups
		out = append(out, r)
	}
	return out, nil
}

// describe is how a rule is named in its audit row: "TEST- → AUTOSET-lab, AUTOSET-x on pihole1", with "prefixes"
// when its groups are name prefixes.
func describe(prefix string, match Match, groups []string, on string) string {
	s := prefix + " → " + strings.Join(groups, ", ")
	if match == MatchPrefixes {
		s += " (prefixes)"
	}
	return s + " on " + on
}

// SetRules replaces every rule. It needs settings.manage, and is audited as client_reset_rules with the rules added
// and removed; a save that changes nothing isn't audited.
func (s *Service) SetRules(ctx context.Context, a rbac.Actor, in []RuleInput) (Settings, error) {
	if err := s.precheck(ctx, a); err != nil {
		return Settings{}, err
	}
	clean, err := checkInput(in)
	if err != nil {
		return Settings{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Rules(ctx)
	if err != nil {
		return Settings{}, err
	}
	err = s.do(ctx, a, func(t *txn) error {
		t.entry.Target = "client_reset:rules"
		var now []string
		for _, r := range clean {
			name, err := t.scopeName(r.Scope, r.ID)
			if err != nil {
				return err
			}
			now = append(now, describe(r.Prefix, r.Match, r.Groups, name))
		}
		if err := t.q.DeleteAllClientResetRules(t.ctx); err != nil {
			return err
		}
		for _, r := range clean {
			groups, err := json.Marshal(r.Groups)
			if err != nil {
				return err
			}
			p := db.AddClientResetRuleParams{CommentPrefix: r.Prefix, GroupMatch: string(r.Match), TargetGroups: string(groups)}
			if r.Scope == ScopeInstance {
				p.InstanceID = sql.NullInt64{Int64: r.ID, Valid: true}
			} else {
				p.GroupID = sql.NullInt64{Int64: r.ID, Valid: true}
			}
			if err := t.q.AddClientResetRule(t.ctx, p); err != nil {
				return err
			}
		}
		var was []string
		for _, r := range before.Rules {
			was = append(was, describe(r.Prefix, r.Match, r.Groups, r.ScopeName))
		}
		var added, removed []string
		for _, d := range now {
			if !slices.Contains(was, d) {
				added = append(added, d)
			}
		}
		for _, d := range was {
			if !slices.Contains(now, d) {
				removed = append(removed, d)
			}
		}
		if len(added)+len(removed) == 0 {
			return errUnchanged
		}
		slices.Sort(added)
		slices.Sort(removed)
		if len(added) > 0 {
			t.entry.Detail["added"] = added
		}
		if len(removed) > 0 {
			t.entry.Detail["removed"] = removed
		}
		return nil
	})
	if err != nil && !errors.Is(err, errUnchanged) {
		return Settings{}, err
	}
	return s.Rules(ctx)
}

// errUnchanged rolls back a save that changes nothing, so it isn't audited.
var errUnchanged = errors.New("no change")

type txn struct {
	ctx   context.Context
	q     *db.Queries
	entry *audit.Entry
}

// do runs fn in a transaction that checks settings.manage, with its audit row. A refusal is recorded as
// permission_denied, as other services do.
func (s *Service) do(ctx context.Context, a rbac.Actor, fn func(t *txn) error) error {
	now := s.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionClientResetRules, IP: a.IP,
		Detail: map[string]any{}}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := rbac.Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		if !set.CanGlobal(rbac.SettingsManage) {
			return rbac.Forbidden(rbac.SettingsManage)
		}
		if err := fn(&txn{ctx: ctx, q: q, entry: &entry}); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case rbac.IsCode(err, rbac.CodeForbidden):
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: "client_reset:rules", Err: err, IP: a.IP,
			Detail: map[string]any{"attempted": audit.ActionClientResetRules, "permission": string(rbac.SettingsManage)},
		}
		if rerr := s.Audit.Record(ctx, s.Store, denied); rerr != nil {
			return fmt.Errorf("audit refusal: %w", rerr)
		}
		return err
	case err != nil:
		return err
	}
	s.Audit.Log(entry)
	return nil
}

// precheck refuses a caller without settings.manage before any work, recording it as the change would.
func (s *Service) precheck(ctx context.Context, a rbac.Actor) error {
	set, err := rbac.Resolve(ctx, s.Store.Read(), a.RoleIDs)
	if err != nil {
		return err
	}
	if set.CanGlobal(rbac.SettingsManage) {
		return nil
	}
	return s.do(ctx, a, func(*txn) error { return nil }) // refused inside, and recorded
}

// scopeName checks what a rule is set on exists, and for a group that it is mirrored (an independent group isn't a
// target: its instances get rules of their own), and returns its name.
func (t *txn) scopeName(scope string, id int64) (string, error) {
	if scope == ScopeInstance {
		r, err := t.q.GetInstance(t.ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return "", validation("id", "There is no instance with ID %d.", id)
		}
		return r.Name, err
	}
	r, err := t.q.GetInstanceGroup(t.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", validation("id", "There is no instance group with ID %d.", id)
	}
	if err != nil {
		return "", err
	}
	if r.Mode != string(rbac.Mirrored) {
		return "", validation("id", "%s is an independent group: client reset rules are set on its instances, or on a mirrored group.", r.Name)
	}
	return r.Name, nil
}
