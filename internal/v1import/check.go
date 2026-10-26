// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1import

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// Prober contacts the Pi-hole and the LDAP server for Check.
type Prober interface {
	// Pihole runs the instance's connection test (log in, read the blocking status) and reads its Pi-hole groups.
	Pihole(ctx context.Context, in instances.Input, pw secrets.Value) ([]piholeapi.Group, error)
	// LDAPBind runs a service bind with the settings and password, as turning LDAP login on does.
	LDAPBind(ctx context.Context, ls auth.LDAPSettings, pw secrets.Value) error
}

// Live is the Prober that contacts the real servers.
type Live struct {
	LDAPCAFile string        // PIHOLE_RBAC_LDAP_CA_FILE, as serve uses it
	Timeout    time.Duration // per request; piholeapi.DefaultTimeout if zero
}

func (l Live) Pihole(ctx context.Context, in instances.Input, pw secrets.Value) ([]piholeapi.Group, error) {
	c, err := piholeapi.New(piholeapi.Options{BaseURL: in.BaseURL, Password: pw, TLSMode: in.TLSMode, CAFile: in.CAFile, Timeout: l.Timeout})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", instances.ErrMisconfigured, err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = c.Close(closeCtx) // log out, so the test doesn't hold one of Pi-hole's API seats
	}()
	if _, err := c.GetStatus(ctx); err != nil {
		return nil, err
	}
	return c.ListGroups(ctx)
}

func (l Live) LDAPBind(ctx context.Context, ls auth.LDAPSettings, pw secrets.Value) error {
	a, err := auth.NewLDAPAuthenticator(ls, func() (secrets.Value, bool) { return pw, true }, l.LDAPCAFile)
	if err != nil {
		return err
	}
	return a.CheckBind(ctx)
}

// Check contacts the Pi-hole and the LDAP server, if the plan has them, and decides what is switched on: the instance
// when its connection test passes and the app will have its password, LDAP login when v1 had it on, the bind test
// passes and the app will have the bind password. It turns group_id_mode's group IDs into names from the instance's
// Pi-hole groups, and warns about rules and protected groups that name groups the Pi-hole doesn't have.
//
// A nil prober checks nothing (--offline): nothing is switched on, and rules that need the groups are left out.
func Check(ctx context.Context, p *Plan, prober Prober, offline string) {
	if prober == nil {
		p.Offline = offline
		p.resolveRules(nil, "the Pi-hole wasn't contacted ("+offline+")")
		p.dropLDAP()
		p.finish()
		return
	}
	p.Checked = true

	inst := &p.Instance
	pw, serveHas := inst.servePassword()
	if !serveHas {
		pw = inst.Password // still worth testing, and the groups are needed either way
	}
	switch {
	case pw.IsZero():
		inst.Test, inst.TestErr = instances.CodePasswordMissing, "there is no password to test with"
		p.resolveRules(nil, "there is no Pi-hole password to read its groups with")
	default:
		groups, err := prober.Pihole(ctx, inst.Input, pw)
		if err != nil {
			inst.Test, inst.TestErr = instances.Kind(err), err.Error()
			p.warnf("The connection test for %s failed (%s), so it is imported switched off. Fix it on Admin → Instances, then enable it.", inst.Input.Name, inst.Test)
			p.resolveRules(nil, "the Pi-hole couldn't be read")
			break
		}
		inst.Test = "ok"
		inst.Enable = serveHas
		p.resolveRules(groups, "")
		p.checkGroups(groups)
	}

	if l := p.LDAP; l != nil && l.Want {
		pw, serveHas := l.servePassword()
		if !serveHas {
			pw = l.Password
		}
		var err error
		if pw.IsZero() {
			err = fmt.Errorf("there is no bind password to test with")
		} else {
			err = prober.LDAPBind(ctx, l.Settings, pw)
		}
		if err != nil {
			l.Test, l.TestErr = "failed", err.Error()
			p.warnf("The LDAP service bind failed, so LDAP login is imported switched off. Fix it on Admin → LDAP, then turn LDAP login on.")
		} else {
			l.Test = "ok"
			l.Enable = serveHas
		}
	}
	if p.LDAP == nil || !p.LDAP.Enable {
		p.dropLDAP()
	}
	p.finish()
}

// resolveRules turns group_id_mode's IDs into the instance's group names. Without the groups (why says why not),
// those rules are left out.
func (p *Plan) resolveRules(groups []piholeapi.Group, why string) {
	names := map[int]string{}
	for _, g := range groups {
		names[g.ID] = g.Name
	}
	var keep []PlannedRule
	warned := false
	for _, r := range p.Rules {
		if r.groupIDs == nil {
			keep = append(keep, r)
			continue
		}
		if groups == nil {
			if !warned {
				p.warnf("client_reset uses group_id_mode, so its group IDs have to be turned into names by reading the Pi-hole's groups, but %s: its rules aren't imported. Add them on Admin → Client reset.", why)
				warned = true
			}
			continue
		}
		var missing []string
		r.Groups = nil
		for _, id := range r.groupIDs {
			if n, ok := names[id]; ok {
				if !slices.Contains(r.Groups, n) {
					r.Groups = append(r.Groups, n)
				}
			} else {
				missing = append(missing, strconv.Itoa(id))
			}
		}
		if len(missing) > 0 && !warned {
			p.warnf("client_reset's target_group_ids %s aren't groups on the Pi-hole, so they are left out of the rules.", strings.Join(missing, ", "))
			warned = true
		}
		if len(r.Groups) == 0 {
			continue
		}
		r.groupIDs = nil
		keep = append(keep, r)
	}
	if len(keep) < len(p.Rules) && len(keep) == 0 && groups != nil {
		p.warnf("None of client_reset's target groups are on the Pi-hole, so no rules are imported.")
	}
	p.Rules = keep
}

// checkGroups warns about rules and protected groups that name groups the Pi-hole doesn't have. They are imported
// anyway: the group may be added later.
func (p *Plan) checkGroups(groups []piholeapi.Group) {
	var names []string
	for _, g := range groups {
		names = append(names, g.Name)
	}
	for _, r := range p.Rules {
		if r.Match != clientreset.MatchPrefixes {
			continue
		}
		if !slices.ContainsFunc(names, func(n string) bool {
			return slices.ContainsFunc(r.Groups, func(pre string) bool { return strings.HasPrefix(n, pre) })
		}) {
			p.warnf("No Pi-hole group starts with %s, so the rule for %s would change nothing until one does.", strings.Join(r.Groups, " or "), r.Prefix)
		}
	}
	var absent []string
	for _, g := range p.Protected {
		if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, g) }) {
			absent = append(absent, g)
		}
	}
	if len(absent) > 0 {
		p.warnf("The protected groups %s aren't on the Pi-hole (yet).", strings.Join(absent, ", "))
	}
}

// finish checks the rules once their groups are known.
func (p *Plan) finish() {
	p.checkRules()
}
