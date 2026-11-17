// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/tokens"
)

func tokenIn(name string, grants ...Grant) TokenInput {
	return TokenInput{Name: name, ExpiresAt: t0.Add(30 * 24 * time.Hour), Grants: grants}
}

func (e *env) userTokens(userID int64) []Token {
	e.t.Helper()
	ts, err := ListUserTokens(e.ctx, e.st.Read(), userID, e.m.now())
	if err != nil {
		e.t.Fatal(err)
	}
	return ts
}

func TestCreateToken(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)

	nt, err := e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("  home assistant ",
		g(BlockingToggle, InstanceScope(e.inst1)), g(AuditView, AllScope()), g(BlockingToggle, InstanceScope(e.inst1))))
	wantCode(t, err, "")
	publicID, hash, ok := tokens.Parse(nt.Secret)
	if !ok || publicID != nt.Token.PublicID {
		t.Fatalf("the new token %q doesn't parse to its public ID %q", nt.Secret, nt.Token.PublicID)
	}
	row, err := e.st.Read().GetAPIToken(e.ctx, publicID)
	if err != nil || !tokens.Equal(row.SecretHash, hash) {
		t.Fatalf("stored hash doesn't match the token (%v)", err)
	}
	want := []Grant{g(BlockingToggle, InstanceScope(e.inst1)), g(AuditView, AllScope())}
	SortGrants(want)
	if nt.Token.Name != "home assistant" || !slices.Equal(nt.Token.Grants, want) || nt.Token.State != TokenActive ||
		!nt.Token.ExpiresAt.Equal(t0.Add(30*24*time.Hour)) || nt.Token.Username != "alice" {
		t.Errorf("new token = %+v", nt.Token)
	}
	listed := e.userTokens(alice)
	if len(listed) != 1 || !slices.Equal(listed[0].Grants, want) || listed[0].State != TokenActive || listed[0].Name != "home assistant" {
		t.Errorf("listed = %+v", listed)
	}

	a := e.lastAudit()
	d := detail(t, a)
	if a.Action != audit.ActionTokenCreate || a.Target != "token:alice/home assistant" || d["token_id"] != publicID ||
		fmt.Sprint(d["grants"]) != fmt.Sprint(grantStrings(want)) || d["expires_at"] != "2026-11-22T12:00:00Z" {
		t.Errorf("audit row = %s %s %s", a.Action, a.Target, a.Detail)
	}
	if strings.Contains(a.Detail, nt.Secret[len(tokens.Prefix)+tokens.PublicIDLen+1:]) {
		t.Error("the audit row contains the secret")
	}
}

func TestCreateTokenRefusals(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	viewers := e.role("viewers", g(TokensUse, AllScope()), g(DomainsView, InstanceScope(e.inst1)))
	vic := e.local("vic", viewers)
	plain := e.local("pat", e.role("plain", g(DomainsView, AllScope())))
	bob := e.ldapUser("bob")
	e.session(bob, t0, e.admin)

	ok := g(DomainsView, InstanceScope(e.inst1))
	for _, c := range []struct {
		name   string
		user   int64
		in     TokenInput
		code   Code
		denied bool
	}{
		{"no tokens.use", plain, tokenIn("x", g(DomainsView, AllScope())), CodeForbidden, true},
		{"an LDAP user", bob, tokenIn("x", ok), CodeConflict, false},
		{"an empty name", alice, tokenIn("   ", ok), CodeValidation, false},
		{"a name too long", alice, tokenIn(strings.Repeat("é", 65), ok), CodeValidation, false},
		{"a control character", alice, tokenIn("a\tb", ok), CodeValidation, false},
		{"expired already", alice, TokenInput{Name: "x", ExpiresAt: t0.Add(-time.Second), Grants: []Grant{ok}}, CodeValidation, false},
		{"expiring now", alice, TokenInput{Name: "x", ExpiresAt: t0, Grants: []Grant{ok}}, CodeValidation, false},
		{"over a year", alice, TokenInput{Name: "x", ExpiresAt: t0.Add(tokens.MaxLifetime + time.Second), Grants: []Grant{ok}}, CodeValidation, false},
		{"no grants", alice, tokenIn("x"), CodeValidation, false},
		{"a management permission", alice, tokenIn("x", ok, g(UsersManage, AllScope())), CodeValidation, false},
		{"tokens.use itself", alice, tokenIn("x", g(TokensUse, AllScope())), CodeValidation, false},
		{"an unknown permission", alice, tokenIn("x", g("domains.delete", AllScope())), CodeValidation, false},
		{"no such instance", alice, tokenIn("x", g(DomainsView, InstanceScope(999))), CodeValidation, false},
		{"drift on an independent group", alice, tokenIn("x", g(DriftView, GroupScope(e.indep))), CodeInvariant, false},
		{"more than the user holds", vic, tokenIn("x", g(DomainsView, AllScope())), CodeForbidden, true},
		{"another permission than the user holds", vic, tokenIn("x", g(DomainsEdit, InstanceScope(e.inst1))), CodeForbidden, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := e.auditCount()
			_, err := e.m.CreateToken(e.ctx, e.actor(c.user), c.in)
			wantCode(t, err, c.code)
			if c.denied {
				wantDenied(t, e, audit.ActionTokenCreate)
			} else if e.auditCount() != before {
				t.Error("a refusal that isn't about permissions was audited")
			}
		})
	}
	if _, err := e.m.CreateToken(e.ctx, e.actor(bob), tokenIn("x", ok)); err != nil {
		if ee, _ := AsError(err); ee.Details["reason"] != "ldap_user" {
			t.Errorf("LDAP refusal details = %v", ee.Details)
		}
	}
	if _, err := e.m.CreateToken(e.ctx, e.actor(vic), tokenIn("x", g(DomainsView, AllScope()))); err != nil {
		if ee, _ := AsError(err); fmt.Sprint(ee.Details["missing"]) != "[domains.view on all]" {
			t.Errorf("missing grants = %v", ee.Details)
		}
	}
	if n := len(e.userTokens(alice)) + len(e.userTokens(vic)) + len(e.userTokens(plain)); n != 0 {
		t.Errorf("%d tokens made by refused requests", n)
	}

	// What vic holds is allowed: the same grant, and a narrower one is the same here.
	_, err := e.m.CreateToken(e.ctx, e.actor(vic), tokenIn("x", ok))
	wantCode(t, err, "")
}

func TestCreateTokenNamesAndLimit(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	carol := e.local("carol", e.admin)
	ok := g(DomainsView, AllScope())

	first, err := e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("cron", ok))
	wantCode(t, err, "")
	_, err = e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("cron", ok))
	wantCode(t, err, CodeConflict)
	if ee, _ := AsError(err); ee.Details["reason"] != "name_taken" {
		t.Errorf("details = %v", ee.Details)
	}
	_, err = e.m.CreateToken(e.ctx, e.actor(carol), tokenIn("cron", ok))
	wantCode(t, err, "") // names are per user
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), first.Token.PublicID, false), "")
	_, err = e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("cron", ok))
	wantCode(t, err, "") // revoking frees the name

	// The limit counts live tokens only: alice has one live and one revoked.
	for i := 1; i < tokens.MaxLive; i++ {
		_, err := e.m.CreateToken(e.ctx, e.actor(alice), tokenIn(fmt.Sprintf("t%d", i), ok))
		wantCode(t, err, "")
	}
	_, err = e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("one too many", ok))
	wantCode(t, err, CodeConflict)
	if ee, _ := AsError(err); ee.Details["reason"] != "too_many_tokens" {
		t.Errorf("details = %v", ee.Details)
	}
	// Once one has expired, there is room again. Expiries are 30 days out.
	now := t0.Add(31 * 24 * time.Hour)
	e.m.Now = func() time.Time { return now }
	_, err = e.m.CreateToken(e.ctx, e.actor(alice), TokenInput{Name: "after expiry", ExpiresAt: now.Add(time.Hour), Grants: []Grant{ok}})
	wantCode(t, err, "")
}

func TestRevokeToken(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	sessionAdmins := e.role("session admins", g(SessionsManage, AllScope()), g(TokensUse, AllScope()), g(DomainsView, AllScope()))
	sam := e.local("sam", sessionAdmins)
	vic := e.local("vic", e.role("token users", g(TokensUse, AllScope()), g(DomainsView, AllScope())))
	nt, err := e.m.CreateToken(e.ctx, e.actor(vic), tokenIn("cron", g(DomainsView, AllScope())))
	wantCode(t, err, "")
	id := nt.Token.PublicID

	// Someone else's token isn't found from the account page, whatever they hold.
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), id, false), CodeNotFound)
	// From the admin list it needs sessions.manage.
	other := e.local("olly", e.role("others", g(DomainsView, AllScope())))
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(other), id, true), CodeForbidden)
	wantDenied(t, e, audit.ActionTokenRevoke)
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), "nosuchtokenxxxxx", true), CodeNotFound)
	if e.userTokens(vic)[0].State != TokenActive {
		t.Fatal("a refused revoke revoked the token")
	}

	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(sam), id, true), "")
	row := e.lastAudit()
	d := detail(t, row)
	if row.Action != audit.ActionTokenRevoke || row.Target != "token:vic/cron" || d["by"] != "admin" || d["owner"] != "vic" || d["token_id"] != id {
		t.Errorf("audit row = %s %s %s", row.Action, row.Target, row.Detail)
	}
	got := e.userTokens(vic)[0]
	if got.State != TokenRevoked || !got.RevokedAt.Equal(t0) {
		t.Errorf("after revoking: %+v", got)
	}

	// Revoking again changes nothing and isn't audited.
	before := e.auditCount()
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(vic), id, false), "")
	if e.auditCount() != before {
		t.Error("revoking a revoked token was audited")
	}

	// Your own, with no permission needed beyond a session.
	mine, err := e.m.CreateToken(e.ctx, e.actor(vic), tokenIn("mine", g(DomainsView, AllScope())))
	wantCode(t, err, "")
	e.tx(func(q *db.Queries) error { return q.DeleteUserRoles(e.ctx, vic) })
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(vic), mine.Token.PublicID, false), "")
	if d := detail(t, e.lastAudit()); d["by"] != "self" || d["owner"] != nil {
		t.Errorf("own revoke detail = %v", d)
	}
}

func TestListTokens(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	carol := e.local("carol", e.admin)
	mk := func(user int64, name string, expires time.Time) string {
		t.Helper()
		nt, err := e.m.CreateToken(e.ctx, e.actor(user), TokenInput{Name: name, ExpiresAt: expires, Grants: []Grant{
			g(DriftView, GroupScope(e.mirror)), g(DomainsView, AllScope()), g(AuditView, AllScope()),
		}})
		wantCode(t, err, "")
		return nt.Token.PublicID
	}
	mk(carol, "soon", t0.Add(time.Hour))
	revoked := mk(alice, "revoked", t0.Add(48*time.Hour))
	mk(alice, "later", t0.Add(48*time.Hour))
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), revoked, false), "")

	e.m.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	all, err := ListAllTokens(e.ctx, e.st.Read(), e.m.now())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tk := range all {
		got = append(got, tk.Username+"/"+tk.Name+"/"+string(tk.State))
	}
	// By username, then newest first: alice's two were made at the same time, so the later one (higher ID) first.
	if !slices.Equal(got, []string{"alice/later/active", "alice/revoked/revoked", "carol/soon/expired"}) {
		t.Errorf("all tokens = %v", got)
	}
	wantGrants := []Grant{g(DomainsView, AllScope()), g(DriftView, GroupScope(e.mirror)), g(AuditView, AllScope())}
	SortGrants(wantGrants)
	for _, tk := range all {
		if !slices.Equal(tk.Grants, wantGrants) {
			t.Errorf("%s grants = %v", tk.Name, tk.Grants)
		}
	}
	if mine := e.userTokens(carol); len(mine) != 1 || mine[0].Name != "soon" {
		t.Errorf("carol's tokens = %+v", mine)
	}
	if none := e.userTokens(e.local("dave", e.admin)); none == nil || len(none) != 0 {
		t.Errorf("no tokens = %#v, want an empty list", none)
	}
}

func TestPruneTokens(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	mk := func(name string, expires time.Time) string {
		t.Helper()
		nt, err := e.m.CreateToken(e.ctx, e.actor(alice), TokenInput{Name: name, ExpiresAt: expires, Grants: []Grant{g(DomainsView, AllScope())}})
		wantCode(t, err, "")
		return nt.Token.PublicID
	}
	mk("expired long ago", t0.Add(time.Hour))
	mk("expired lately", t0.Add(20*24*time.Hour))
	mk("live", t0.Add(300*24*time.Hour))
	revoked := mk("revoked long ago", t0.Add(300*24*time.Hour))
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), revoked, false), "")

	n, err := PruneTokens(e.ctx, e.st, t0.Add(40*24*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v, want 2", n, err)
	}
	var left []string
	for _, tk := range e.userTokens(alice) {
		left = append(left, tk.Name)
	}
	slices.Sort(left)
	if !slices.Equal(left, []string{"expired lately", "live"}) {
		t.Errorf("left = %v", left)
	}
}

func TestCheckGroupModeChangeTokens(t *testing.T) {
	e := newEnv(t)
	alice := e.local("alice", e.admin)
	q := e.st.Read()
	nt, err := e.m.CreateToken(e.ctx, e.actor(alice), tokenIn("drift monitor", g(DriftView, GroupScope(e.mirror))))
	wantCode(t, err, "")

	err = CheckGroupModeChange(e.ctx, q, e.mirror, Independent, t0)
	wantCode(t, err, CodeInvariant)
	if ee, _ := AsError(err); !slices.Equal(ee.Details["api_tokens"].([]string), []string{`"drift monitor" (alice)`}) ||
		len(ee.Details["roles"].([]string)) != 0 {
		t.Errorf("details = %v", ee.Details)
	}
	// An expired token doesn't hold the group, and nor does a revoked one.
	wantCode(t, CheckGroupModeChange(e.ctx, q, e.mirror, Independent, t0.Add(31*24*time.Hour)), "")
	wantCode(t, e.m.RevokeToken(e.ctx, e.actor(alice), nt.Token.PublicID, false), "")
	wantCode(t, CheckGroupModeChange(e.ctx, q, e.mirror, Independent, t0), "")
}

// What the token form offers: only token permissions the user holds, at the scopes they hold them.
func TestGrantableForToken(t *testing.T) {
	topo := NewTopology(
		[]int64{1, 2, 3, 4},
		map[int64]GroupMode{10: Independent, 20: Mirrored},
		map[int64][]int64{10: {1, 2}, 20: {3, 4}},
	)
	set := NewSet([]Grant{
		g(DomainsView, AllScope()),
		g(DomainsEdit, GroupScope(10)), // an independent group: the group and its members
		g(BlockingToggle, InstanceScope(3)),
		g(DriftView, GroupScope(20)),
		g(AuditView, AllScope()),
		g(UsersManage, AllScope()), // not a token permission
		g(TokensUse, AllScope()),   // nor this
	}, topo)
	got := map[Permission]string{}
	var order []Permission
	for _, ts := range GrantableForToken(set) {
		got[ts.Permission.Name] = fmt.Sprintf("all=%v instances=%v groups=%v", ts.All, ts.Instances, ts.Groups)
		order = append(order, ts.Permission.Name)
	}
	want := map[Permission]string{
		DomainsView:    "all=true instances=[1 2 3 4] groups=[10 20]",
		DomainsEdit:    "all=false instances=[1 2] groups=[10]",
		BlockingToggle: "all=false instances=[3] groups=[]",
		DriftView:      "all=false instances=[] groups=[20]",
		AuditView:      "all=true instances=[] groups=[]",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: %s, want %s", p, got[p], w)
		}
	}
	if !slices.IsSortedFunc(order, func(a, b Permission) int {
		return slices.IndexFunc(catalogue, func(i Info) bool { return i.Name == a }) - slices.IndexFunc(catalogue, func(i Info) bool { return i.Name == b })
	}) {
		t.Errorf("not in catalogue order: %v", order)
	}
	// Each offered grant is one CreateToken would accept: held and valid.
	for _, ts := range GrantableForToken(set) {
		for _, id := range ts.Instances {
			if gr := g(ts.Permission.Name, InstanceScope(id)); !set.Holds(gr) || ValidateGrant(topo, gr) != nil {
				t.Errorf("offered %s, which can't be granted", gr)
			}
		}
	}
}
