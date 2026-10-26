// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1import

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// Report writes what the plan creates, then its errors, warnings and things to do by hand. It never writes a secret:
// only whether each one is stored or which variable it is expected in.
func (p *Plan) Report(w io.Writer) {
	r := &reporter{w: w}

	r.section("Files read")
	r.line("config.json       %s", p.From.Config)
	r.line("permissions.json  %s", orText(p.From.Permissions, "none: v1's built-in permissions"))
	r.line("local-users.json  %s", orText(p.From.Users, "none: no local users"))

	inst := p.Instance
	r.section("Instance")
	r.line("%s  %s", inst.Input.Name, inst.Input.BaseURL)
	switch {
	case inst.Password.IsZero() && !inst.EnvSet:
		r.line("password: none")
	case inst.Store:
		r.line("password: v1's, stored encrypted")
	default:
		r.line("password: from %s (%s)", secrets.InstanceVar(inst.Input.EnvName), setOrNot(inst.EnvSet))
	}
	r.line("connection test: %s", p.testText(inst.Test, inst.TestErr))
	r.line("imported %s", onOff(inst.Enable))

	r.section("Roles")
	r.line("admin: the builtin admin role (every permission)")
	for _, role := range p.Roles {
		r.line("%s: %s", role.Name, orText(strings.Join(role.Permissions, ", "), "no permissions"))
	}

	r.section(fmt.Sprintf("Local users (%d)", len(p.Users)))
	for _, u := range p.Users {
		r.line("%s: %s", u.Username, orText(strings.Join(u.Roles, ", "), "no roles"))
	}
	if n := p.admins(); n > 0 {
		r.line("First-run setup will be closed: %d local %s.", n, plural(n, "admin"))
	} else {
		r.line("First-run setup stays open: no local admin.")
	}

	r.section("LDAP")
	if l := p.LDAP; l == nil {
		r.line("not imported")
	} else {
		s := l.Settings
		r.line("%s, bind as %s", s.URL, s.BindDN)
		r.line("users under %s matching %s, TLS %s", s.BaseDN, s.UserFilter, s.TLSMode)
		switch {
		case l.Password.IsZero() && !l.EnvSet:
			r.line("bind password: none")
		case l.Store:
			r.line("bind password: v1's, stored encrypted")
		default:
			r.line("bind password: from PIHOLE_RBAC_LDAP_BIND_PASSWORD (%s)", setOrNot(l.EnvSet))
		}
		if l.Want {
			r.line("service bind: %s", p.ldapTestText())
		}
		for _, m := range p.Mappings {
			r.line("mapping: %s ← %s", m.Role, m.DN)
		}
	}
	r.line("login methods: %s", joinMethods(p.Methods))

	r.section(fmt.Sprintf("Notification channels (%d)", len(p.Channels)))
	for _, ch := range p.Channels {
		in := ch.Input
		dest := ""
		if in.Kind == notify.Matrix {
			dest = in.Matrix.Homeserver + " room " + in.Matrix.RoomID
		}
		secret := "none"
		switch {
		case ch.Store:
			secret = "v1's, stored encrypted"
		case in.EnvName != "":
			secret = fmt.Sprintf("from %s (%s)", secrets.ChannelVar(in.EnvName), setOrNot(ch.EnvSet))
		}
		if dest != "" {
			dest = ": " + dest
		}
		r.line("%s (%s, %s)%s", in.Name, ch.From, onOff(in.Enabled), dest)
		r.line("    secret: %s; events: %s", secret, orText(strings.Join(in.Events, ", "), "none"))
	}
	if len(p.Protected) > 0 {
		r.line("protected groups on %s: %s", inst.Input.Name, strings.Join(p.Protected, ", "))
	}

	r.section("Client reset")
	for _, rule := range p.Rules {
		match := ""
		if rule.Match == clientreset.MatchPrefixes {
			match = " (group name prefixes)"
		}
		r.line("rule on %s: comments starting %s → %s%s", inst.Input.Name, rule.Prefix, strings.Join(rule.Groups, ", "), match)
	}
	if len(p.Rules) == 0 {
		r.line("no rules")
	}
	if s := p.Schedule; s != nil {
		r.line("schedule: daily at %s %s, %s", s.Time, s.TimeZone, onOff(s.Enabled))
	} else {
		r.line("schedule: not set (off)")
	}

	if len(p.Errors) > 0 {
		r.section(fmt.Sprintf("Problems to fix before --apply (%d)", len(p.Errors)))
		r.list(p.Errors)
	}
	if len(p.Warnings) > 0 {
		r.section(fmt.Sprintf("Warnings (%d)", len(p.Warnings)))
		r.list(p.Warnings)
	}
	if len(p.ToDo) > 0 {
		r.section("To do by hand")
		r.list(p.ToDo)
	}
}

type reporter struct {
	w io.Writer
}

func (r *reporter) section(title string) {
	fmt.Fprintf(r.w, "\n%s\n", title)
}

func (r *reporter) line(format string, args ...any) {
	fmt.Fprintf(r.w, "  "+format+"\n", args...)
}

func (r *reporter) list(items []string) {
	for _, s := range items {
		fmt.Fprintf(r.w, "  - %s\n", s)
	}
}

func orText(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func setOrNot(set bool) string {
	if set {
		return "set"
	}
	return "not set"
}

func onOff(on bool) string {
	if on {
		return "switched on"
	}
	return "switched off"
}

func joinMethods(ms []auth.Method) string {
	s := make([]string, len(ms))
	for i, m := range ms {
		s[i] = string(m)
	}
	return strings.Join(s, ", ")
}

func (p *Plan) testText(result, detail string) string {
	switch {
	case !p.Checked:
		return "not run (" + p.Offline + ")"
	case result == "ok":
		return "passed"
	case detail != "":
		return fmt.Sprintf("failed, %s: %s", result, detail)
	}
	return "failed, " + result
}

func (p *Plan) ldapTestText() string {
	l := p.LDAP
	switch {
	case !p.Checked:
		return "not run (" + p.Offline + ")"
	case l.Test == "ok" && !slices.Contains(p.Methods, auth.MethodLDAP):
		return "passed, but LDAP login stays off until the app has the bind password"
	case l.Test == "ok":
		return "passed"
	}
	return "failed: " + l.TestErr
}
