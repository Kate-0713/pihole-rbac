// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notifications

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Protected groups: Pi-hole group names, per instance or per mirrored group, whose new clients raise the
// protected_group_add alert. The client write handler asks ProtectedFor which names apply to the instance it changed,
// and records the protected groups the client was added to in its audit row; the notifier turns that into the alert.

// Scope kinds.
const (
	ScopeInstance = "instance"
	ScopeGroup    = "group"
)

// Protected is one scope's protected Pi-hole groups.
type Protected struct {
	Scope  string // ScopeInstance or ScopeGroup
	ID     int64
	Name   string   // the instance's or group's name
	Groups []string // Pi-hole group names, sorted ignoring case
}

// Choice is an instance or mirrored group protected groups can be set on.
type Choice struct {
	ID   int64
	Name string
}

// ProtectedSettings is the protected groups and what they can be set on. The choices come with them because someone
// with notifications.manage may not be able to list instances otherwise.
type ProtectedSettings struct {
	Entries   []Protected
	Instances []Choice
	Groups    []Choice // mirrored groups only
}

const (
	maxProtectedScopes   = 200
	maxProtectedPerScope = 100
	maxPiholeGroupRunes  = 255
)

// ProtectedGroups returns the protected groups and the instances and mirrored groups they can be set on.
func (s *Service) ProtectedGroups(ctx context.Context) (ProtectedSettings, error) {
	q := s.Store.Read()
	rows, err := q.ListProtectedGroups(ctx)
	if err != nil {
		return ProtectedSettings{}, err
	}
	out := ProtectedSettings{Entries: []Protected{}, Instances: []Choice{}, Groups: []Choice{}}
	for _, r := range rows {
		scope, id, name := ScopeInstance, r.InstanceID.Int64, r.InstanceName
		if r.GroupID.Valid {
			scope, id, name = ScopeGroup, r.GroupID.Int64, r.GroupName
		}
		if n := len(out.Entries); n > 0 && out.Entries[n-1].Scope == scope && out.Entries[n-1].ID == id {
			out.Entries[n-1].Groups = append(out.Entries[n-1].Groups, r.PiholeGroup)
			continue
		}
		out.Entries = append(out.Entries, Protected{Scope: scope, ID: id, Name: name, Groups: []string{r.PiholeGroup}})
	}
	instances, err := q.ListInstances(ctx)
	if err != nil {
		return ProtectedSettings{}, err
	}
	for _, i := range instances {
		out.Instances = append(out.Instances, Choice{ID: i.ID, Name: i.Name})
	}
	groups, err := q.ListInstanceGroups(ctx)
	if err != nil {
		return ProtectedSettings{}, err
	}
	for _, g := range groups {
		if g.Mode == "mirrored" {
			out.Groups = append(out.Groups, Choice{ID: g.ID, Name: g.Name})
		}
	}
	return out, nil
}

// ProtectedFor returns the protected Pi-hole group names that apply to an instance: its own and its mirrored group's.
func (s *Service) ProtectedFor(ctx context.Context, instanceID int64) ([]string, error) {
	return s.Store.Read().ProtectedGroupsForInstance(ctx, sql.NullInt64{Int64: instanceID, Valid: true})
}

// ProtectedAdded returns which of the groups a client was added to are protected, by the names Pi-hole uses:
// those in after but not before, matched against protected ignoring case.
func ProtectedAdded(before, after, protected []string) []string {
	var out []string
	for _, g := range after {
		if containsFold(before, g) || !containsFold(protected, g) || containsFold(out, g) {
			continue
		}
		out = append(out, g)
	}
	return out
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}

// ProtectedInput is one scope's protected groups as a request gives them.
type ProtectedInput struct {
	Scope  string
	ID     int64
	Groups []string
}

// SetProtectedGroups replaces every protected group. Removing any tells the channels that receive
// protected_group_add, so the alert can't be switched off unseen. Audited as protected_groups_update.
func (s *Service) SetProtectedGroups(ctx context.Context, a rbac.Actor, in []ProtectedInput) (ProtectedSettings, error) {
	if err := s.precheck(ctx, a, audit.ActionProtectedGroups); err != nil {
		return ProtectedSettings{}, err
	}
	if len(in) > maxProtectedScopes {
		return ProtectedSettings{}, validation("entries", "At most %d instances and groups.", maxProtectedScopes)
	}
	type key struct {
		scope string
		id    int64
	}
	seen := map[key]bool{}
	clean := make([]ProtectedInput, 0, len(in))
	for _, e := range in {
		if e.Scope != ScopeInstance && e.Scope != ScopeGroup {
			return ProtectedSettings{}, validation("scope", "A scope is instance or group.")
		}
		k := key{e.Scope, e.ID}
		if seen[k] {
			return ProtectedSettings{}, validation("entries", "Each instance and group is listed once.")
		}
		seen[k] = true
		if len(e.Groups) > maxProtectedPerScope {
			return ProtectedSettings{}, validation("pihole_groups", "At most %d Pi-hole groups each.", maxProtectedPerScope)
		}
		var names []string
		for _, g := range e.Groups {
			g = strings.TrimSpace(g)
			if n := utf8.RuneCountInString(g); n == 0 || n > maxPiholeGroupRunes || strings.IndexFunc(g, unicode.IsControl) >= 0 {
				return ProtectedSettings{}, validation("pihole_groups",
					"A Pi-hole group name is 1-%d characters, with no control characters.", maxPiholeGroupRunes)
			}
			if !containsFold(names, g) {
				names = append(names, g)
			}
		}
		if len(names) == 0 {
			continue // a scope with no groups is simply not stored
		}
		slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
		clean = append(clean, ProtectedInput{Scope: e.Scope, ID: e.ID, Groups: names})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.ProtectedGroups(ctx)
	if err != nil {
		return ProtectedSettings{}, err
	}
	var added, removed []string
	err = s.do(ctx, a, audit.ActionProtectedGroups, func(t *txn) error {
		t.entry.Target = "notifications:protected_groups"
		names := map[key]string{}
		for _, e := range clean {
			name, err := t.scopeName(e.Scope, e.ID)
			if err != nil {
				return err
			}
			names[key{e.Scope, e.ID}] = name
		}
		if err := t.q.DeleteAllProtectedGroups(t.ctx); err != nil {
			return err
		}
		for _, e := range clean {
			for _, g := range e.Groups {
				p := db.AddProtectedGroupParams{PiholeGroup: g}
				if e.Scope == ScopeInstance {
					p.InstanceID = sql.NullInt64{Int64: e.ID, Valid: true}
				} else {
					p.GroupID = sql.NullInt64{Int64: e.ID, Valid: true}
				}
				if err := t.q.AddProtectedGroup(t.ctx, p); err != nil {
					return err
				}
			}
		}
		// Added and removed, as "<group> on <instance or group>".
		was := map[key][]string{}
		for _, e := range before.Entries {
			was[key{e.Scope, e.ID}] = e.Groups
			names[key{e.Scope, e.ID}] = e.Name
		}
		now := map[key][]string{}
		for _, e := range clean {
			now[key{e.Scope, e.ID}] = e.Groups
		}
		for k, gs := range now {
			for _, g := range gs {
				if !containsFold(was[k], g) {
					added = append(added, g+" on "+names[k])
				}
			}
		}
		for k, gs := range was {
			for _, g := range gs {
				if !containsFold(now[k], g) {
					removed = append(removed, g+" on "+names[k])
				}
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
		return ProtectedSettings{}, err
	}
	if len(removed) > 0 {
		s.warnProtectedRemoved(ctx, a.Username, removed)
	}
	return s.ProtectedGroups(ctx)
}

// errUnchanged rolls back a save that changes nothing, so it isn't audited.
var errUnchanged = errors.New("no change")

// scopeName checks a scope exists, and for a group that it is mirrored (an independent group isn't a target, so
// nothing is ever written through it), and returns its name.
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
	if r.Mode != "mirrored" {
		return "", validation("id", "%s is an independent group: protected groups are set on its instances, or on a mirrored group.", r.Name)
	}
	return r.Name, nil
}

// warnProtectedRemoved tells every channel that receives protected_group_add, and can send, which alerts stop.
func (s *Service) warnProtectedRemoved(ctx context.Context, by string, removed []string) {
	channels, err := s.List(context.WithoutCancel(ctx))
	if err != nil || s.Notifier == nil {
		return
	}
	for _, ch := range channels {
		if !ch.Enabled || !slices.Contains(ch.Events, notify.EventProtectedGroupAdd) {
			continue
		}
		v, _, problem := s.secretOf(ch)
		if problem != "" {
			continue
		}
		m := &notify.Message{}
		m.Text("⚠️ Protected groups changed by ").Bold(by).Text(": no more alerts when a client is added to ")
		for i, r := range removed {
			if i > 0 {
				m.Text(", ")
			}
			m.Text(r)
		}
		m.Text(".")
		s.Notifier.Enqueue(notify.Job{Destination: destination(ch, v), Message: m, Event: "guard", Guard: true, By: by})
	}
}
