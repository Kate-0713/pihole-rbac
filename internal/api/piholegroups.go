// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholegroups"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Pi-hole groups (not instance groups) are named by name in the request body, since names can hold spaces and other
// characters that don't survive a path. Pi-hole doesn't protect its Default group (ID 0): it can be renamed, disabled
// and deleted, and a delete strips it from everything. So the app refuses renaming and deleting it, and disabling it
// needs ?confirm=true. The app refers to Pi-hole groups by name in client reset rules and protected groups: renaming
// or deleting one of those needs ?confirm=true, and a rename updates them where the old name is gone.

const maxPiholeGroupNameRunes = 255

// checkGroupName checks a Pi-hole group name: 1 to 255 characters, no control characters, and no spaces at the start
// or end, which would make two groups look alike.
func checkGroupName(field, name string) error {
	if err := checkText(field, name, maxPiholeGroupNameRunes); err != nil {
		return err
	}
	if name == "" || strings.TrimSpace(name) != name {
		return invalid(field, "A Pi-hole group name is 1 to %d characters, with no spaces at the start or end.", maxPiholeGroupNameRunes)
	}
	return nil
}

func piholeGroupJSON(g piholeapi.Group) gen.PiholeGroup {
	return gen.PiholeGroup{Id: g.ID, Name: g.Name, Comment: g.Comment, Enabled: g.Enabled}
}

// findGroup returns the Pi-hole group called name (exactly) among groups.
func findGroup(groups []piholeapi.Group, name string) (piholeapi.Group, bool) {
	i := slices.IndexFunc(groups, func(g piholeapi.Group) bool { return g.Name == name })
	if i < 0 {
		return piholeapi.Group{}, false
	}
	return groups[i], true
}

// reportOf is a mirrored group's drift report, when the target is one and its primary was read.
func (s *Server) reportOf(tg target) (instances.Report, bool) {
	if !tg.isGroup() {
		return instances.Report{}, false
	}
	rep, ok := s.Drift.Report(tg.t.ID)
	return rep, ok && rep.PrimaryOK
}

// primaryGroup reads the Pi-hole groups of the instance, or of the mirrored group's primary, and returns the one a
// change names: a 404 when it isn't there. Unlike other writes through a group, these need the primary to answer,
// since the Default and confirmation checks are made on it. done, when not "", is a name the primary may have
// instead: the new name of a rename being retried on members that failed, which the primary has already taken.
func (s *Server) primaryGroup(ctx context.Context, tg target, name, done string) (piholeapi.Group, error) {
	var groups []piholeapi.Group
	if err := s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		var err error
		groups, err = c.ListGroups(ctx)
		return err
	}); err != nil {
		var pf *piholeFailure
		if errors.As(err, &pf) && tg.isGroup() {
			pf.PrimaryOf = tg.group
		}
		return piholeapi.Group{}, err
	}
	g, ok := findGroup(groups, name)
	if !ok && done != "" {
		g, ok = findGroup(groups, done)
	}
	if !ok {
		p := tg.primary()
		e := &rbac.Error{Code: rbac.CodeNotFound, Message: "There's no Pi-hole group " + quoted([]string{name}) + " on " + p.name + ".",
			Details: map[string]any{"instance": p.name}}
		if tg.isGroup() {
			e.Message = "There's no Pi-hole group " + quoted([]string{name}) + " on " + p.name + ", the primary of " + tg.group + "."
			e.Details["group"] = tg.group
		}
		return piholeapi.Group{}, e
	}
	return g, nil
}

// groupScopes are the scopes of the app's references a change through tg touches: an instance and the mirrored group
// it belongs to (whose references apply to it as a member), or a mirrored group and its members.
func (s *Server) groupScopes(ctx context.Context, tg target) ([]piholegroups.Scope, error) {
	if tg.isGroup() {
		out := []piholegroups.Scope{{GroupID: tg.t.ID}}
		for _, m := range tg.members {
			out = append(out, piholegroups.Scope{InstanceID: m.id})
		}
		return out, nil
	}
	out := []piholegroups.Scope{{InstanceID: tg.t.ID}}
	id, _, ok, err := s.Instances.MirroredGroupOf(ctx, tg.t.ID)
	if err != nil {
		return nil, err
	}
	if ok {
		out = append(out, piholegroups.Scope{GroupID: id})
	}
	return out, nil
}

// refsIn returns the references whose scope is one of scopes.
func refsIn(refs []piholegroups.Ref, scopes []piholegroups.Scope) []piholegroups.Ref {
	return slices.DeleteFunc(slices.Clone(refs), func(r piholegroups.Ref) bool { return !slices.Contains(scopes, r.Scope) })
}

// refView decides which references the caller may see in full: client reset rules with settings.manage, protected
// groups with notifications.manage. Counts are always shown.
type refView struct{ rules, protected bool }

func (s *Server) refView(ctx context.Context) (refView, error) {
	set, err := s.permissions(ctx)
	if err != nil {
		return refView{}, err
	}
	return refView{rules: set.CanGlobal(rbac.SettingsManage), protected: set.CanGlobal(rbac.NotifyManage)}, nil
}

func (v refView) shows(r piholegroups.Ref) bool {
	if r.Kind == piholegroups.KindResetRule {
		return v.rules
	}
	return v.protected
}

// refJSON describes a reference for the API.
func refJSON(r piholegroups.Ref) gen.PiholeGroupReference {
	out := gen.PiholeGroupReference{
		Kind: gen.PiholeGroupReferenceKind(r.Kind), ScopeName: r.ScopeName,
		Scope: gen.PiholeGroupReferenceScopeInstance, ScopeId: r.Scope.InstanceID,
	}
	if r.Scope.GroupID != 0 {
		out.Scope, out.ScopeId = gen.PiholeGroupReferenceScopeGroup, r.Scope.GroupID
	}
	if r.Kind == piholegroups.KindResetRule {
		prefix, match := r.Prefix, gen.PiholeGroupReferenceMatch(r.Match)
		out.CommentPrefix, out.Match, out.Names = &prefix, &match, slices.Clone(r.Groups)
	} else {
		out.Names = []string{r.Name}
	}
	return out
}

// list builds the API's references: the counts of every one, and the ones v shows.
func (v refView) list(refs []piholegroups.Ref, each func(i int, r *gen.PiholeGroupReference)) gen.PiholeGroupReferences {
	c := piholegroups.Count(refs)
	out := gen.PiholeGroupReferences{
		Counts: gen.PiholeGroupReferenceCounts{ClientResetRules: c.ResetRules, ProtectedGroups: c.Protected},
		Items:  []gen.PiholeGroupReference{},
	}
	for i, r := range refs {
		if !v.shows(r) {
			continue
		}
		item := refJSON(r)
		if each != nil {
			each(i, &item)
		}
		out.Items = append(out.Items, item)
	}
	return out
}

// refDetail describes a reference for an audit row, in full: the audit log is read with audit.view.
func refDetail(r piholegroups.Ref) map[string]any {
	d := map[string]any{"kind": string(r.Kind), "scope": r.Scope.String(), "scope_name": r.ScopeName}
	if r.Kind == piholegroups.KindResetRule {
		d["comment_prefix"], d["match"], d["names"] = r.Prefix, r.Match, r.Groups
	} else {
		d["names"] = []string{r.Name}
	}
	return d
}

// confirmRefs is the 409 for a rename or delete of a Pi-hole group the app refers to, and for disabling Default.
func confirmRefs(message string, v refView, refs []piholegroups.Ref, defaultGroup bool) error {
	details := map[string]any{}
	if len(refs) > 0 {
		details["references"] = v.list(refs, nil)
	}
	if defaultGroup {
		details["default_group"] = true
	}
	return &rbac.Error{Code: rbac.CodeConfirmation, Message: message, Details: details}
}

func (s *Server) AddPiholeGroup(ctx context.Context, req gen.AddPiholeGroupRequestObject) (gen.AddPiholeGroupResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	if err := checkGroupName("name", b.Name); err != nil {
		return nil, err
	}
	g := piholeapi.Group{Name: b.Name, Enabled: b.Enabled == nil || *b.Enabled}
	if b.Comment != nil {
		if err := checkText("comment", *b.Comment, maxCommentRunes); err != nil {
			return nil, err
		}
		g.Comment = *b.Comment
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.PiholeGroupsEdit)
	if err != nil {
		return nil, err
	}
	if tg, err = tg.only(req.Params.Members); err != nil {
		return nil, err
	}
	saved := make([]piholeapi.Group, len(tg.members))
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		if err := c.AddGroup(ctx, g); err != nil {
			return err
		}
		saved[i] = g
		if groups, err := c.ListGroups(ctx); err == nil {
			if got, ok := findGroup(groups, g.Name); ok {
				saved[i] = got
			}
		}
		return nil
	})
	for i, m := range tg.members {
		if outs[i].ran {
			s.auditPihole(ctx, m, audit.ActionPiholeGroupAdd, outs[i].callErr, map[string]any{
				"name": g.Name, "comment": g.Comment, "enabled": g.Enabled,
			})
		}
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, err
	}
	results := groupResults(outs, saved)
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.AddPiholeGroup207JSONResponse{Results: results}, nil
	}
	return gen.AddPiholeGroup200JSONResponse{Results: results}, nil
}

func groupResults(outs []outcome, saved []piholeapi.Group) []gen.PiholeGroupWriteResult {
	return resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.PiholeGroupWriteResult {
		r := gen.PiholeGroupWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			g := piholeGroupJSON(saved[i])
			r.Entry = &g
		}
		return r
	})
}

// defaultOn is the failure of a rename or delete on a member whose group of that name is its Default group.
func defaultOn(tg target, m instanceRef, what string) error {
	msg := "The Default group on " + m.name + " can't be " + what + "."
	if tg.isGroup() {
		return &memberError{code: string(rbac.CodeValidation), message: msg}
	}
	return invalid("name", "%s", msg)
}

// UpdatePiholeGroup renames a Pi-hole group, or changes its comment or enabled flag. Each instance reads the group
// first (Pi-hole's PUT creates a group that doesn't exist, renames a missing one silently, and enables one when the
// flag is left out) and gets the change merged into the group as read; a change that changes nothing isn't sent or
// audited. A rename then updates the app's references where the old name is gone, in the transaction that writes
// the audit rows.
func (s *Server) UpdatePiholeGroup(ctx context.Context, req gen.UpdatePiholeGroupRequestObject) (gen.UpdatePiholeGroupResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	if err := checkGroupName("name", b.Name); err != nil {
		return nil, err
	}
	rename := b.NewName != nil && *b.NewName != b.Name
	if b.NewName != nil {
		if err := checkGroupName("new_name", *b.NewName); err != nil {
			return nil, err
		}
	}
	if b.Comment != nil {
		if err := checkText("comment", *b.Comment, maxCommentRunes); err != nil {
			return nil, err
		}
	}
	if !rename && b.Comment == nil && b.Enabled == nil {
		return nil, invalid("body", "Give a new name, a comment or the enabled flag to change.")
	}
	full, err := s.resolveTarget(ctx, req.Target, rbac.PiholeGroupsEdit)
	if err != nil {
		return nil, err
	}
	tg, err := full.only(req.Params.Members)
	if err != nil {
		return nil, err
	}
	done := ""
	if rename && req.Params.Members != nil {
		done = *b.NewName
	}
	cur, err := s.primaryGroup(ctx, tg, b.Name, done)
	if err != nil {
		return nil, err
	}
	if cur.ID == defaultGroupID && rename {
		return nil, invalid("name", "The Default group can't be renamed.")
	}
	view, err := s.refView(ctx)
	if err != nil {
		return nil, err
	}
	scopes, err := s.groupScopes(ctx, full)
	if err != nil {
		return nil, err
	}
	var refs []piholegroups.Ref
	if rename {
		all, err := piholegroups.Load(ctx, s.Store.Read())
		if err != nil {
			return nil, err
		}
		refs = refsIn(all, scopes)
	}
	disablingDefault := cur.ID == defaultGroupID && b.Enabled != nil && !*b.Enabled && cur.Enabled
	if named := piholegroups.Matching(refs, scopes, b.Name); (len(named) > 0 || disablingDefault) && !confirmed(req.Params.Confirm) {
		msg := "The app refers to this Pi-hole group: confirm to rename it, and the references will follow."
		if disablingDefault {
			msg = "Disabling the Default group stops the domains and lists assigned only to Default applying to the clients in it, which on most installs turns filtering off. Confirm to go ahead."
		}
		return nil, confirmRefs(msg, view, named, disablingDefault)
	}

	n := len(tg.members)
	saved, before, details := make([]piholeapi.Group, n), make([]piholeapi.Group, n), make([]map[string]any, n)
	left := make([][]string, n) // each member's group names once the change is made
	attempted := make([]bool, n)
	outs, ferr := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			left[i] = append(left[i], g.Name)
		}
		g, ok := findGroup(groups, b.Name)
		if !ok {
			return tg.missing(m, "There's no Pi-hole group "+quoted([]string{b.Name})+" on "+m.name+".")
		}
		if g.ID == defaultGroupID && rename {
			return defaultOn(tg, m, "renamed")
		}
		before[i] = g
		after := g
		if rename {
			after.Name = *b.NewName
		}
		if b.Comment != nil {
			after.Comment = *b.Comment
		}
		if b.Enabled != nil {
			after.Enabled = *b.Enabled
		}
		saved[i] = after
		if after == g {
			return nil
		}
		details[i] = map[string]any{"name": g.Name, "comment": after.Comment, "enabled": after.Enabled,
			"comment_changed": after.Comment != g.Comment}
		if rename {
			details[i]["new_name"] = after.Name
		}
		attempted[i] = true
		if rename {
			err = c.RenameGroup(ctx, g.Name, after)
		} else {
			err = c.UpdateGroup(ctx, after)
		}
		if err == nil && rename {
			left[i] = slices.DeleteFunc(left[i], func(n string) bool { return n == g.Name })
			left[i] = append(left[i], after.Name)
		}
		return err
	})

	entries := make([]*audit.Entry, n)
	for i, m := range tg.members {
		if !attempted[i] {
			continue
		}
		action := audit.ActionPiholeGroupUpdate
		if saved[i].Enabled != before[i].Enabled {
			action = audit.ActionPiholeGroupDisable
			if saved[i].Enabled {
				action = audit.ActionPiholeGroupEnable
			}
		}
		e := s.piholeEntry(ctx, m, action, outs[i].callErr, details[i])
		entries[i] = &e
	}
	var renamedRefs *gen.PiholeGroupRenameReferences
	if rename && anyOK(outs) {
		renamedRefs = s.renameRefs(ctx, full, tg, outs, left, refs, b.Name, *b.NewName, view, entries)
	} else {
		s.recordEntries(ctx, entries)
	}
	s.pokeDrift(ctx, tg)
	if ferr != nil {
		return nil, ferr
	}
	results := groupResults(outs, saved)
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.UpdatePiholeGroup207JSONResponse{Results: results, References: renamedRefs}, nil
	}
	return gen.UpdatePiholeGroup200JSONResponse{Results: results, References: renamedRefs}, nil
}

// recordEntries writes audit rows on their own, as auditPihole does.
func (s *Server) recordEntries(ctx context.Context, entries []*audit.Entry) {
	for _, e := range entries {
		if e == nil {
			continue
		}
		if aerr := s.Audit.Record(context.WithoutCancel(ctx), s.Store, *e); aerr != nil {
			s.Logger.Error("recording a pi-hole write", "action", e.Action, "instance", e.InstanceName, "err", aerr)
		}
	}
}

// renameRefs updates the app's references after Pi-hole renamed a group on at least one instance, and writes the
// rename's audit rows in the same transaction. A scope counts as renamed when the old name is gone from it: an
// instance that renamed; a mirrored group whose every enabled member did (those a retry left out are read again).
// If the transaction fails, the audit rows are written on their own, and the answer says the references weren't
// updated.
func (s *Server) renameRefs(ctx context.Context, full, tg target, outs []outcome, left [][]string, refs []piholegroups.Ref,
	from, to string, view refView, entries []*audit.Entry) *gen.PiholeGroupRenameReferences {
	renamed := map[int64]bool{} // by instance ID
	names := map[int64][]string{}
	for i, m := range tg.members {
		renamed[m.id] = outs[i].ok() && outs[i].ran
		names[m.id] = left[i]
	}
	if full.isGroup() {
		for _, m := range full.members {
			if _, done := renamed[m.id]; done {
				continue
			}
			var groups []piholeapi.Group
			err := s.call(ctx, m, func(ctx context.Context, c *piholeapi.Client) error {
				var err error
				groups, err = c.ListGroups(ctx)
				return err
			})
			_, hasOld := findGroup(groups, from)
			_, hasNew := findGroup(groups, to)
			renamed[m.id] = err == nil && !hasOld && hasNew
			for _, g := range groups {
				names[m.id] = append(names[m.id], g.Name)
			}
		}
	}
	where := piholegroups.Renamed{
		Renamed: func(sc piholegroups.Scope) bool {
			if sc.GroupID == 0 {
				return renamed[sc.InstanceID]
			}
			if !full.isGroup() || sc.GroupID != full.t.ID {
				return false // a direct rename on one member: the group's other members still have the old name
			}
			for _, m := range full.members {
				if !renamed[m.id] {
					return false
				}
			}
			return true
		},
		Left: func(sc piholegroups.Scope) []string {
			if sc.GroupID == 0 {
				return names[sc.InstanceID]
			}
			var all []string
			for _, m := range full.members {
				all = append(all, names[m.id]...)
			}
			return all
		},
	}
	plan := piholegroups.PlanRename(refs, from, to, where)

	// Each row lists its own instance's references; the group's own go in the first row (the primary's, unless a
	// retry left it out).
	rowFor := func(sc piholegroups.Scope) *audit.Entry {
		for i, m := range tg.members {
			if entries[i] != nil && (sc.GroupID != 0 || m.id == sc.InstanceID) {
				return entries[i]
			}
		}
		return nil
	}
	for _, c := range plan.Changes {
		if e := rowFor(c.Ref.Scope); e != nil {
			d := refDetail(c.Ref)
			d["before"], d["names"], d["dropped"] = c.Before, c.After, c.Dropped
			e.Detail["references_updated"] = append(anyList(e.Detail["references_updated"]), d)
		}
	}
	for _, c := range plan.Checks {
		if e := rowFor(c.Ref.Scope); e != nil {
			d := refDetail(c.Ref)
			d["reason"] = c.Reason
			e.Detail["references_to_check"] = append(anyList(e.Detail["references_to_check"]), d)
		}
	}

	out := &gen.PiholeGroupRenameReferences{}
	changed := make([]piholegroups.Ref, len(plan.Changes))
	for i, c := range plan.Changes {
		changed[i] = c.Ref
	}
	out.Updated = view.list(changed, func(i int, r *gen.PiholeGroupReference) {
		c := plan.Changes[i]
		before := slices.Clone(c.Before)
		r.Before, r.Names = &before, slices.Clone(c.After)
		if c.Dropped {
			dropped := true
			r.Dropped = &dropped
		}
	})
	checked := make([]piholegroups.Ref, len(plan.Checks))
	for i, c := range plan.Checks {
		checked[i] = c.Ref
	}
	out.ToCheck = view.list(checked, func(i int, r *gen.PiholeGroupReference) {
		reason := gen.PiholeGroupReferenceReason(plan.Checks[i].Reason)
		r.Reason = &reason
	})

	// Pi-hole has already acted, so the references and the rows are written even if the client has gone away.
	bg := context.WithoutCancel(ctx)
	err := s.Store.WithTx(bg, func(q *db.Queries) error {
		if err := piholegroups.Apply(bg, q, plan); err != nil {
			return err
		}
		for _, e := range entries {
			if e != nil {
				if _, err := audit.Insert(bg, q, *e); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		s.Logger.Error("updating references after a pi-hole group rename", "from", from, "to", to, "err", err)
		msg := "Pi-hole renamed the group, but the app couldn't update its references to the old name. Check them by hand."
		out.Error = &msg
		for _, e := range entries {
			if e != nil {
				e.Detail["references_error"] = true
			}
		}
		s.recordEntries(ctx, entries)
		return out
	}
	for _, e := range entries {
		if e != nil {
			s.Audit.Log(*e)
		}
	}
	return out
}

func anyList(v any) []any {
	l, _ := v.([]any)
	return l
}

// DeletePiholeGroup deletes a Pi-hole group, which Pi-hole takes off every domain, client and list. The app's
// references to it are listed for someone to fix, never removed.
func (s *Server) DeletePiholeGroup(ctx context.Context, req gen.DeletePiholeGroupRequestObject) (gen.DeletePiholeGroupResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	if err := checkGroupName("name", b.Name); err != nil {
		return nil, err
	}
	full, err := s.resolveTarget(ctx, req.Target, rbac.PiholeGroupsEdit)
	if err != nil {
		return nil, err
	}
	tg, err := full.only(req.Params.Members)
	if err != nil {
		return nil, err
	}
	cur, err := s.primaryGroup(ctx, tg, b.Name, "")
	if err != nil {
		return nil, err
	}
	if cur.ID == defaultGroupID {
		return nil, invalid("name", "The Default group can't be deleted.")
	}
	view, err := s.refView(ctx)
	if err != nil {
		return nil, err
	}
	scopes, err := s.groupScopes(ctx, full)
	if err != nil {
		return nil, err
	}
	all, err := piholegroups.Load(ctx, s.Store.Read())
	if err != nil {
		return nil, err
	}
	named := piholegroups.Matching(all, scopes, b.Name)
	if len(named) > 0 && !confirmed(req.Params.Confirm) {
		return nil, confirmRefs("The app refers to this Pi-hole group: confirm to delete it. The references will be left for you to fix.", view, named, false)
	}

	n := len(tg.members)
	details, attempted := make([]map[string]any, n), make([]bool, n)
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		g, ok := findGroup(groups, b.Name)
		if !ok {
			return nil // already gone
		}
		if g.ID == defaultGroupID {
			return defaultOn(tg, m, "deleted")
		}
		details[i] = map[string]any{"name": g.Name, "comment": g.Comment, "enabled": g.Enabled}
		attempted[i] = true
		return c.DeleteGroup(ctx, g.Name)
	})
	// Each row lists its own instance's references; the group's own go in the first row.
	first := true
	for i, m := range tg.members {
		if !attempted[i] {
			continue
		}
		var mine []any
		for _, r := range named {
			if (r.Scope.GroupID != 0 && first) || (r.Scope.GroupID == 0 && r.Scope.InstanceID == m.id) {
				mine = append(mine, refDetail(r))
			}
		}
		if len(mine) > 0 {
			details[i]["references"] = mine
		}
		first = false
		s.auditPihole(ctx, m, audit.ActionPiholeGroupDelete, outs[i].callErr, details[i])
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, err
	}
	results := resultsOf(outs, func(_ int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DeleteResult {
		return gen.DeleteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
	})
	var refsOut *gen.PiholeGroupReferences
	if len(named) > 0 {
		l := view.list(named, nil)
		refsOut = &l
	}
	multi, err := s.finishWrite(ctx, outs, results)
	if err != nil {
		return nil, err
	}
	if multi {
		return gen.DeletePiholeGroup207JSONResponse{Results: results, References: refsOut}, nil
	}
	return gen.DeletePiholeGroup200JSONResponse{Results: results, References: refsOut}, nil
}

// GetPiholeGroupUsage counts what is in a Pi-hole group on the instance or the primary, and the app's references to
// it, for the delete dialog. It needs piholegroups.edit: it is part of deleting.
func (s *Server) GetPiholeGroupUsage(ctx context.Context, req gen.GetPiholeGroupUsageRequestObject) (gen.GetPiholeGroupUsageResponseObject, error) {
	name := req.Params.Name
	if err := checkGroupName("name", name); err != nil {
		return nil, err
	}
	tg, err := s.resolveTarget(ctx, req.Target, rbac.PiholeGroupsEdit)
	if err != nil {
		return nil, err
	}
	var out gen.PiholeGroupUsage
	found := false
	err = s.call(ctx, tg.primary(), func(ctx context.Context, c *piholeapi.Client) error {
		groups, err := c.ListGroups(ctx)
		if err != nil {
			return err
		}
		g, ok := findGroup(groups, name)
		if !ok {
			return nil
		}
		found = true
		out.Name, out.Id = g.Name, g.ID
		domains, err := c.ListDomains(ctx)
		if err != nil {
			return err
		}
		clients, err := c.ListClients(ctx)
		if err != nil {
			return err
		}
		lists, err := c.ListLists(ctx)
		if err != nil {
			return err
		}
		for _, d := range domains {
			if slices.Contains(d.Groups, g.ID) {
				out.Domains++
			}
		}
		for _, ce := range clients {
			if slices.Contains(ce.Groups, g.ID) {
				out.Clients++
			}
		}
		for _, l := range lists {
			if slices.Contains(l.Groups, g.ID) {
				out.Lists++
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		p := tg.primary()
		return nil, &rbac.Error{Code: rbac.CodeNotFound, Message: "There's no Pi-hole group " + quoted([]string{name}) + " on " + p.name + ".",
			Details: map[string]any{"instance": p.name}}
	}
	view, err := s.refView(ctx)
	if err != nil {
		return nil, err
	}
	scopes, err := s.groupScopes(ctx, tg)
	if err != nil {
		return nil, err
	}
	all, err := piholegroups.Load(ctx, s.Store.Read())
	if err != nil {
		return nil, err
	}
	out.References = view.list(piholegroups.Matching(all, scopes, name), nil)
	return gen.GetPiholeGroupUsage200JSONResponse(out), nil
}
