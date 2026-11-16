// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// roleID returns the ID of the role addRoleUser made for a user.
func (e *testEnv) roleID(user string) int64 {
	e.t.Helper()
	roles, err := e.st.Read().ListRoles(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, r := range roles {
		if r.Name == user+"-role" {
			return r.ID
		}
	}
	e.t.Fatalf("no role for %s", user)
	return 0
}

func setRoleTOTP(c *client, roleID int64, required bool) response {
	return c.do(http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/totp-required", roleID), gen.RoleTOTPRequired{Required: required})
}

func setUserTOTP(c *client, userID int64, policy string) response {
	return c.do(http.MethodPut, userPath(userID, "/totp-policy"), gen.UserTOTPPolicy{Policy: gen.TOTPPolicy(policy)})
}

func sessionOf(t *testing.T, c *client) gen.CurrentSession {
	t.Helper()
	res := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	mustStatus(t, res, http.StatusOK)
	return decode[gen.CurrentSession](t, res)
}

// held reports whether the client's session is being held to setting two-factor login up: an ordinary route refuses
// it with totp_setup_required, and the session says so.
func held(t *testing.T, c *client) bool {
	t.Helper()
	res := c.do(http.MethodGet, "/api/v1/sessions", nil)
	refused := res.Code == http.StatusForbidden && res.errorCode() == "totp_setup_required"
	if !refused && res.Code != http.StatusOK {
		t.Fatalf("GET /sessions: %d %s", res.Code, res.Body)
	}
	if said := sessionOf(t, c).TotpSetupRequired; said != refused {
		t.Fatalf("the session says totp_setup_required=%v, but a request was refused=%v", said, refused)
	}
	return refused
}

// TestTOTPRequiredByRole: a role that requires two-factor login holds its holders' open sessions to setting it up, at
// once, on every route but the ones for doing that. Setting it up lets them through. Other users aren't touched.
func TestTOTPRequiredByRole(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addUser("admin", "admin-password-1", true)
	aliceID := e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	alice := e.loggedIn("alice", "alice-password-1")
	bob := e.loggedIn("bob", "bob-password-123")
	role := e.roleID("alice")

	if held(t, alice) {
		t.Fatal("held before anything requires it")
	}
	res := setRoleTOTP(admin, role, true)
	mustStatus(t, res, http.StatusOK)
	if r := decode[gen.Role](t, res); !r.TotpRequired || r.Name != "alice-role" {
		t.Errorf("the answer: %+v", r)
	}
	rows := e.auditRows()
	if last := rows[len(rows)-1]; last.Action != "role_totp_update" || last.Target != "role:alice-role" ||
		last.Username != "admin" || !strings.Contains(last.Detail, `"required":true`) {
		t.Errorf("audit row: %+v", last)
	}
	// Setting it again changes nothing and isn't audited.
	mustStatus(t, setRoleTOTP(admin, role, true), http.StatusOK)
	if n := len(e.auditRows()); n != len(rows) {
		t.Errorf("setting it again was audited (%d rows)", n-len(rows))
	}

	// The session alice already had is held from her next request.
	if !held(t, alice) {
		t.Fatal("alice's open session isn't held")
	}
	if held(t, bob) || held(t, admin) {
		t.Error("someone without the role is held")
	}
	list := decode[gen.UserList](t, admin.do(http.MethodGet, "/api/v1/users", nil)).Users
	if u := userNamed(t, list, "alice"); !u.TotpRequired || u.TotpPolicy != "roles" || u.TotpEnabled {
		t.Errorf("alice in the users list: %+v", u)
	}
	if u := userNamed(t, list, "bob"); u.TotpRequired {
		t.Errorf("bob in the users list: %+v", u)
	}

	// Everything that needs a session is refused, reads and writes alike, whatever it would have answered.
	for _, r := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/targets", nil},
		{http.MethodGet, "/api/v1/sessions", nil},
		{http.MethodGet, "/api/v1/system/version", nil},
		{http.MethodGet, "/api/v1/users", nil},
		{http.MethodPost, "/api/v1/auth/password", gen.PasswordChange{CurrentPassword: "alice-password-1", NewPassword: "alice-password-2"}},
		{http.MethodPost, totpBase + "/disable", gen.TOTPDisable{Password: "alice-password-1", Code: "123456"}},
		{http.MethodPost, totpBase + "/recovery-codes", gen.TOTPCode{Code: "123456"}},
		{http.MethodPut, userPath(aliceID, "/totp-policy"), gen.UserTOTPPolicy{Policy: "exempt"}},
		{http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/totp-required", role), gen.RoleTOTPRequired{Required: false}},
	} {
		res := alice.do(r.method, r.path, r.body)
		if res.Code != http.StatusForbidden || res.errorCode() != "totp_setup_required" {
			t.Errorf("%s %s while held: %d %s", r.method, r.path, res.Code, res.Body)
		}
	}
	// A new login is held too, and says so.
	again := e.client("10.0.0.6:1")
	res = again.login("alice", "alice-password-1")
	mustStatus(t, res, http.StatusOK)
	if !decode[gen.CurrentSession](t, res).TotpSetupRequired {
		t.Error("a new login doesn't say setup is required")
	}

	// What stays open: the CSRF token, the status, setup and confirm.
	alice.fetchCSRF()
	if st := totpStatus(t, alice); !st.Required || st.Enabled {
		t.Errorf("status while held: %+v", st)
	}
	app, _ := setupTOTP(t, alice, clock)
	if !held(t, alice) {
		t.Error("a secret that isn't confirmed lifted the hold")
	}
	mustStatus(t, alice.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: app.code()}), http.StatusOK)
	if held(t, alice) {
		t.Error("still held after setting it up")
	}

	// Logging out is open to a held session.
	mustStatus(t, again.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized) // ended when alice confirmed
	e.addRoleUser("carol", "carol-password-1", rbac.DomainsView)
	carol := e.loggedIn("carol", "carol-password-1")
	mustStatus(t, setRoleTOTP(admin, e.roleID("carol"), true), http.StatusOK)
	mustStatus(t, carol.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)

	// Taking the requirement away lets a holder without it back in.
	dave := func() *client {
		e.addRoleUser("dave", "dave-password-123", rbac.DomainsView)
		return e.loggedIn("dave", "dave-password-123")
	}()
	mustStatus(t, setRoleTOTP(admin, e.roleID("dave"), true), http.StatusOK)
	if !held(t, dave) {
		t.Fatal("dave isn't held")
	}
	res = setRoleTOTP(admin, e.roleID("dave"), false)
	mustStatus(t, res, http.StatusOK)
	if decode[gen.Role](t, res).TotpRequired || held(t, dave) {
		t.Error("dave is still held after the requirement was taken away")
	}
	mustStatus(t, setRoleTOTP(admin, e.roleID("dave"), false), http.StatusOK)
	if n := auditCount(e, "role_totp_update", "success"); n != 4 {
		t.Errorf("%d role_totp_update rows, want 4", n)
	}
}

// TestSetRoleTOTPRequiredRefusals: it needs roles.manage and every grant the role has; the builtin admin role can be
// set; and requiring it is refused while nobody could set it up.
func TestSetRoleTOTPRequiredRefusals(t *testing.T) {
	available := true
	e, clock := newTOTPEnv(t, func(o *Options) { o.Roles.TOTPAvailable = func() bool { return available } })
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("rolesonly", "roles-password-1", rbac.RolesManage)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	rolesOnly := e.loggedIn("rolesonly", "roles-password-1")
	alice := e.loggedIn("alice", "alice-password-1")

	if res := setRoleTOTP(alice, e.roleID("alice"), true); res.Code != http.StatusForbidden || res.errorCode() != "forbidden" {
		t.Errorf("without roles.manage: %d %s", res.Code, res.Body)
	}
	// roles.manage alone doesn't cover the admin role's grants, in either direction.
	if res := setRoleTOTP(rolesOnly, adminRoleID, true); res.Code != http.StatusForbidden {
		t.Errorf("a role above the caller: %d %s", res.Code, res.Body)
	}
	if res := setRoleTOTP(admin, 999, true); res.Code != http.StatusNotFound {
		t.Errorf("a role that doesn't exist: %d %s", res.Code, res.Body)
	}
	res := admin.do(http.MethodPut, fmt.Sprintf("/api/v1/roles/%d/totp-required", adminRoleID), map[string]any{"required": "yes"})
	if res.Code != http.StatusBadRequest {
		t.Errorf("a value that isn't a boolean: %d %s", res.Code, res.Body)
	}

	available = false
	res = setRoleTOTP(admin, e.roleID("alice"), true)
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "no_master_key" {
		t.Errorf("requiring it with no master key: %d %s", res.Code, res.Body)
	}
	if held(t, alice) {
		t.Error("a refused requirement holds alice")
	}
	available = true

	// The builtin admin role, whose own row can't be changed, can require it. The admin who set it is held at once.
	res = setRoleTOTP(admin, adminRoleID, true)
	mustStatus(t, res, http.StatusOK)
	if r := decode[gen.Role](t, res); !r.TotpRequired || !r.Builtin {
		t.Errorf("the admin role: %+v", r)
	}
	if !held(t, admin) {
		t.Fatal("the admin isn't held by their own role's requirement")
	}
	// Held, the admin can't take the requirement back off, or exempt themselves: setting it up is the way through.
	if res := setRoleTOTP(admin, adminRoleID, false); res.errorCode() != "totp_setup_required" {
		t.Errorf("taking it off while held: %d %s", res.Code, res.Body)
	}
	enableTOTP(t, admin, clock)
	if held(t, admin) {
		t.Fatal("still held after setting it up")
	}
	// Taking a requirement away is allowed with no master key: it can't lock anyone out.
	available = false
	mustStatus(t, setRoleTOTP(admin, adminRoleID, false), http.StatusOK)
}

// TestUserTOTPPolicy: a user's own setting wins over their roles' in both directions, and going back to roles hands
// the decision back.
func TestUserTOTPPolicy(t *testing.T) {
	e, _ := newTOTPEnv(t)
	e.addUser("admin", "admin-password-1", true)
	aliceID := e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	bobID := e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	alice := e.loggedIn("alice", "alice-password-1")
	bob := e.loggedIn("bob", "bob-password-123")
	mustStatus(t, setRoleTOTP(admin, e.roleID("alice"), true), http.StatusOK)

	check := func(when string, wantAlice, wantBob bool) {
		t.Helper()
		if got := held(t, alice); got != wantAlice {
			t.Errorf("%s: alice held = %v, want %v", when, got, wantAlice)
		}
		if got := held(t, bob); got != wantBob {
			t.Errorf("%s: bob held = %v, want %v", when, got, wantBob)
		}
	}
	check("alice's role requires it", true, false)

	res := setUserTOTP(admin, aliceID, "exempt")
	mustStatus(t, res, http.StatusOK)
	if u := decode[gen.User](t, res); u.TotpPolicy != "exempt" || u.TotpRequired {
		t.Errorf("alice, exempt: %+v", u)
	}
	res = setUserTOTP(admin, bobID, "required")
	mustStatus(t, res, http.StatusOK)
	if u := decode[gen.User](t, res); u.TotpPolicy != "required" || !u.TotpRequired {
		t.Errorf("bob, required: %+v", u)
	}
	check("each with their own setting", false, true)
	// An exempt user can still turn it on, and the status says it isn't required of them.
	if st := totpStatus(t, alice); st.Required || !st.Available {
		t.Errorf("alice's status while exempt: %+v", st)
	}

	before := len(e.auditRows())
	mustStatus(t, setUserTOTP(admin, bobID, "required"), http.StatusOK)
	if len(e.auditRows()) != before {
		t.Error("setting what is already set was audited")
	}
	mustStatus(t, setUserTOTP(admin, aliceID, "roles"), http.StatusOK)
	mustStatus(t, setUserTOTP(admin, bobID, "roles"), http.StatusOK)
	check("back to their roles", true, false)

	var rows []string
	for _, r := range e.auditRows() {
		if r.Action == "user_totp_policy" {
			rows = append(rows, r.Target+" "+r.Detail)
		}
	}
	if len(rows) != 4 || !strings.Contains(rows[0], "user:alice") || !strings.Contains(rows[0], `"policy":"exempt"`) ||
		!strings.Contains(rows[0], `"was":"roles"`) || !strings.Contains(rows[3], `"policy":"roles"`) || !strings.Contains(rows[3], `"was":"required"`) {
		t.Errorf("user_totp_policy rows: %q", rows)
	}
}

// TestSetUserTOTPPolicyRefusals: it needs users.manage and every grant the user has (invariant 7), a known setting,
// and for "required" a way to set two-factor login up.
func TestSetUserTOTPPolicyRefusals(t *testing.T) {
	available := true
	e, _ := newTOTPEnv(t, func(o *Options) { o.Roles.TOTPAvailable = func() bool { return available } })
	adminID := e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("hr", "hr-password-123", rbac.UsersManage, rbac.DomainsView)
	aliceID := e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	hr := e.loggedIn("hr", "hr-password-123")
	alice := e.loggedIn("alice", "alice-password-1")

	if res := setUserTOTP(alice, aliceID, "exempt"); res.Code != http.StatusForbidden || res.errorCode() != "forbidden" {
		t.Errorf("without users.manage: %d %s", res.Code, res.Body)
	}
	// hr has users.manage but not the admin's grants, so can neither exempt the admin nor hold them to setup.
	for _, p := range []string{"exempt", "required"} {
		if res := setUserTOTP(hr, adminID, p); res.Code != http.StatusForbidden {
			t.Errorf("%s for a user above the caller: %d %s", p, res.Code, res.Body)
		}
	}
	if res := setUserTOTP(admin, 999, "required"); res.Code != http.StatusNotFound {
		t.Errorf("a user who doesn't exist: %d %s", res.Code, res.Body)
	}
	for _, p := range []string{"", "optional", "Required"} {
		if res := setUserTOTP(admin, aliceID, p); res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
			t.Errorf("setting %q: %d %s", p, res.Code, res.Body)
		}
	}
	// hr can set it for someone they could manage anyway.
	mustStatus(t, setUserTOTP(hr, aliceID, "required"), http.StatusOK)
	mustStatus(t, setUserTOTP(hr, aliceID, "roles"), http.StatusOK)

	available = false
	res := setUserTOTP(admin, aliceID, "required")
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "no_master_key" {
		t.Errorf("requiring it with no master key: %d %s", res.Code, res.Body)
	}
	mustStatus(t, setUserTOTP(admin, aliceID, "exempt"), http.StatusOK)
	if held(t, alice) || held(t, admin) {
		t.Error("someone is held after refused changes")
	}
}

// TestTOTPRequiredAfterRemoval: a user who must use two-factor login and has it on isn't held. When an admin removes
// it, their next login is by password alone and goes straight to setting it up again.
func TestTOTPRequiredAfterRemoval(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addUser("admin", "admin-password-1", true)
	aliceID := e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	alice := e.loggedIn("alice", "alice-password-1")
	app, _ := enableTOTP(t, alice, clock)
	mustStatus(t, setUserTOTP(admin, aliceID, "required"), http.StatusOK)
	if held(t, alice) {
		t.Fatal("held though two-factor login is on")
	}
	// Required and on: turning it off is allowed (to move to a new phone), and holds the session at once.
	mustStatus(t, alice.do(http.MethodPost, totpBase+"/disable", gen.TOTPDisable{Password: "alice-password-1", Code: app.code()}), http.StatusNoContent)
	if !held(t, alice) {
		t.Fatal("not held after turning it off while required")
	}
	app, _ = enableTOTP(t, alice, clock)

	mustStatus(t, admin.do(http.MethodDelete, userPath(aliceID, "/totp"), nil), http.StatusOK)
	back := e.client("10.0.0.7:1")
	res := back.login("alice", "alice-password-1")
	mustStatus(t, res, http.StatusOK) // no code asked for: there is no secret to check one against
	if !decode[gen.CurrentSession](t, res).TotpSetupRequired || !held(t, back) {
		t.Error("the login after removal isn't held to setting it up")
	}
	_ = app
}

// TestTOTPRequiredLDAP: an LDAP user is covered through the role their group maps to.
func TestTOTPRequiredLDAP(t *testing.T) {
	clock := &totpClock{at: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	const staffDN = "CN=Staff,OU=Groups,DC=example,DC=local"
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{staffDN}},
	}}
	e := newLDAPEnv(t, dir, withTOTP(clock))
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("staff", "staff-password-1", rbac.DomainsView) // only for its role
	e.mapGroup(staffDN, e.roleID("staff"))
	admin := e.loggedIn("admin", "admin-password-1")
	dana := e.loggedIn("dana", "dana-password")

	mustStatus(t, setRoleTOTP(admin, e.roleID("staff"), true), http.StatusOK)
	if !held(t, dana) {
		t.Fatal("an LDAP user holding the role through a group isn't held")
	}
	list := decode[gen.UserList](t, admin.do(http.MethodGet, "/api/v1/users", nil)).Users
	if u := userNamed(t, list, "dana"); !u.TotpRequired || u.Source != "ldap" {
		t.Errorf("dana in the users list: %+v", u)
	}
	enableTOTP(t, dana, clock)
	if held(t, dana) {
		t.Error("still held after setting it up")
	}
}
