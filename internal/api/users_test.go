// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func userPath(id int64, suffix string) string { return fmt.Sprintf("/api/v1/users/%d%s", id, suffix) }

func userNamed(t *testing.T, users []gen.User, name string) gen.User {
	t.Helper()
	i := slices.IndexFunc(users, func(u gen.User) bool { return u.Username == name })
	if i < 0 {
		t.Fatalf("no user %q in %+v", name, users)
	}
	return users[i]
}

func roleNames(u gen.User) []string {
	out := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		out[i] = r.Name
	}
	return out
}

// noSecretsAudited fails if any audit line or row contains one of the passwords.
func noSecretsAudited(t *testing.T, e *testEnv, passwords ...string) {
	t.Helper()
	var all strings.Builder
	for _, l := range e.auditLines() {
		all.WriteString(l)
	}
	for _, r := range e.auditRows() {
		all.WriteString(r.Detail)
		all.WriteString(r.Target)
	}
	for _, p := range passwords {
		if strings.Contains(all.String(), p) {
			t.Errorf("a password reached the audit log: %q", p)
		}
	}
}

func TestListUsers(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,OU=People,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("staffer", "staffer-password", rbac.DomainsView)
	e.addRoleUser("hr", "hr-password-123", rbac.UsersManage)
	e.addUser("zed", "zed-password-12", false)
	e.loggedIn("dana", "dana-password") // gives dana a row and a session holding admin

	admin := e.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodGet, "/api/v1/users", nil)
	mustStatus(t, res, http.StatusOK)
	users := decode[gen.UserList](t, res).Users
	var names []string
	for _, u := range users {
		names = append(names, u.Username)
	}
	if !slices.Equal(names, []string{"admin", "dana", "hr", "staffer", "zed"}) {
		t.Errorf("users sorted by name: %v", names)
	}

	a := userNamed(t, users, "admin")
	if a.Source != "local" || a.Disabled || a.LdapDn != nil || a.LastLoginAt == nil || !slices.Equal(roleNames(a), []string{"admin"}) || !a.Manageable {
		t.Errorf("admin: %+v", a)
	}
	d := userNamed(t, users, "dana")
	if d.Source != "ldap" || d.LdapDn == nil || *d.LdapDn != dir.users["dana"].dn || !slices.Equal(roleNames(d), []string{"admin"}) {
		t.Errorf("dana (LDAP, roles from her session): %+v", d)
	}
	if z := userNamed(t, users, "zed"); len(z.Roles) != 0 || z.LastLoginAt != nil || !z.Manageable {
		t.Errorf("zed (no roles, never logged in): %+v", z)
	}

	// manageable follows the caller's grants: hr holds only users.manage.
	hr := e.loggedIn("hr", "hr-password-123")
	users = decode[gen.UserList](t, hr.do(http.MethodGet, "/api/v1/users", nil)).Users
	for name, want := range map[string]bool{"admin": false, "dana": false, "staffer": false, "hr": true, "zed": true} {
		if got := userNamed(t, users, name).Manageable; got != want {
			t.Errorf("hr sees %s manageable=%v, want %v", name, got, want)
		}
	}

	one := decode[gen.User](t, admin.do(http.MethodGet, userPath(a.Id, ""), nil))
	if one.Username != "admin" || !slices.Equal(roleNames(one), []string{"admin"}) {
		t.Errorf("GET /users/%d: %+v", a.Id, one)
	}
	if res := admin.do(http.MethodGet, userPath(999, ""), nil); res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
		t.Errorf("missing user: %d %s", res.Code, res.Body)
	}

	staff := e.loggedIn("staffer", "staffer-password")
	if res := staff.do(http.MethodGet, "/api/v1/users", nil); res.Code != http.StatusForbidden ||
		!strings.Contains(res.Body.String(), `"permission":"users.manage"`) {
		t.Errorf("without users.manage: %d %s", res.Code, res.Body)
	}
}

func TestUserLifecycle(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("staffer", "staffer-password", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	staffRole := roleNamed(t, decode[gen.RoleList](t, admin.do(http.MethodGet, "/api/v1/roles", nil)).Roles, "staffer-role")

	const first, second = "first-password-1", "second-password-2"
	res := admin.do(http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "  Erin ", Password: first, RoleIds: []int64{staffRole.Id}})
	mustStatus(t, res, http.StatusCreated)
	erin := decode[gen.User](t, res)
	if erin.Username != "erin" || erin.Source != "local" || erin.Disabled || !slices.Equal(roleNames(erin), []string{"staffer-role"}) {
		t.Fatalf("created: %+v", erin)
	}
	if res := admin.do(http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "erin", Password: first, RoleIds: []int64{}}); res.Code != http.StatusConflict || res.errorCode() != "conflict" {
		t.Errorf("duplicate username: %d %s", res.Code, res.Body)
	}

	// Erin logs in from two browsers.
	erin1 := e.loggedIn("erin", first)
	erin2 := e.loggedIn("erin", first)

	// New roles reach her sessions at once.
	res = admin.do(http.MethodPut, userPath(erin.Id, "/roles"), gen.UserRoles{RoleIds: []int64{staffRole.Id, adminRoleID}})
	mustStatus(t, res, http.StatusOK)
	if got := roleNames(decode[gen.User](t, res)); !slices.Equal(got, []string{"admin", "staffer-role"}) {
		t.Errorf("roles after the change: %v", got)
	}
	mustStatus(t, erin1.do(http.MethodGet, "/api/v1/users", nil), http.StatusOK)

	// A new password ends her sessions.
	mustStatus(t, admin.do(http.MethodPost, userPath(erin.Id, "/password"), gen.UserPassword{Password: second}), http.StatusNoContent)
	mustStatus(t, erin1.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	mustStatus(t, erin2.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	if res := e.client("10.0.0.2:1").login("erin", first); res.Code != http.StatusUnauthorized {
		t.Errorf("old password still works: %d", res.Code)
	}
	erin1 = e.loggedIn("erin", second)

	// Disabling ends her session and stops her logging in; enabling lets her back.
	res = admin.do(http.MethodPost, userPath(erin.Id, "/disable"), nil)
	mustStatus(t, res, http.StatusOK)
	if !decode[gen.User](t, res).Disabled {
		t.Error("disable: user not disabled")
	}
	mustStatus(t, erin1.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	if res := e.client("10.0.0.3:1").login("erin", second); res.Code != http.StatusUnauthorized {
		t.Errorf("disabled user logged in: %d", res.Code)
	}
	res = admin.do(http.MethodPost, userPath(erin.Id, "/enable"), nil)
	mustStatus(t, res, http.StatusOK)
	if decode[gen.User](t, res).Disabled {
		t.Error("enable: user still disabled")
	}
	e.loggedIn("erin", second)

	mustStatus(t, admin.do(http.MethodDelete, userPath(erin.Id, ""), nil), http.StatusNoContent)
	mustStatus(t, admin.do(http.MethodGet, userPath(erin.Id, ""), nil), http.StatusNotFound)
	if res := e.client("10.0.0.4:1").login("erin", second); res.Code != http.StatusUnauthorized {
		t.Errorf("deleted user logged in: %d", res.Code)
	}

	for _, want := range []string{"user_create", "user_roles", "user_password", "user_disable", "user_enable", "user_delete"} {
		if !slices.Contains(e.auditActions(), want) {
			t.Errorf("no %s in the audit log: %v", want, e.auditActions())
		}
	}
	noSecretsAudited(t, e, first, second)
}

func TestUserRefusals(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir)
	adminID := e.addUser("admin", "admin-password-1", true)
	hrID := e.addRoleUser("hr", "hr-password-123", rbac.UsersManage)
	e.loggedIn("dana", "dana-password")
	dana, _ := e.user("dana")
	admin := e.loggedIn("admin", "admin-password-1")
	hr := e.loggedIn("hr", "hr-password-123")

	tests := []struct {
		name         string
		c            *client
		method, path string
		body         any
		status       int
		code         string
	}{
		{"short password", admin, http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "x", Password: "short", RoleIds: []int64{}}, 400, "validation_failed"},
		{"bad username", admin, http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "no spaces", Password: "long-enough-pw", RoleIds: []int64{}}, 400, "validation_failed"},
		{"unknown role", admin, http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "x", Password: "long-enough-pw", RoleIds: []int64{99}}, 400, "validation_failed"},
		{"role id 0", admin, http.MethodPut, userPath(hrID, "/roles"), gen.UserRoles{RoleIds: []int64{0}}, 400, "validation_failed"},
		{"missing user", admin, http.MethodPost, userPath(999, "/disable"), nil, 404, "not_found"},
		{"LDAP password", admin, http.MethodPost, userPath(dana.ID, "/password"), gen.UserPassword{Password: "long-enough-pw"}, 400, "validation_failed"},
		{"LDAP roles", admin, http.MethodPut, userPath(dana.ID, "/roles"), gen.UserRoles{RoleIds: []int64{}}, 400, "validation_failed"},
		// Invariant 3: hr can't give a role holding more than they do.
		{"escalate on create", hr, http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "x", Password: "long-enough-pw", RoleIds: []int64{adminRoleID}}, 403, "forbidden"},
		{"escalate own roles", hr, http.MethodPut, userPath(hrID, "/roles"), gen.UserRoles{RoleIds: []int64{adminRoleID}}, 403, "forbidden"},
		// Invariant 7: hr can't act on an account that holds more than they do.
		{"reset admin password", hr, http.MethodPost, userPath(adminID, "/password"), gen.UserPassword{Password: "taken-over-pw"}, 403, "forbidden"},
		{"disable admin", hr, http.MethodPost, userPath(adminID, "/disable"), nil, 403, "forbidden"},
		{"delete admin", hr, http.MethodDelete, userPath(adminID, ""), nil, 403, "forbidden"},
		{"disable LDAP admin", hr, http.MethodPost, userPath(dana.ID, "/disable"), nil, 403, "forbidden"},
		// Invariant 4: your own account needs confirming.
		{"disable self", admin, http.MethodPost, userPath(adminID, "/disable"), nil, 409, "confirmation_required"},
		{"delete self", admin, http.MethodDelete, userPath(adminID, ""), nil, 409, "confirmation_required"},
		// Invariant 2: admin is the only enabled local admin (dana is LDAP, which doesn't count).
		{"disable last admin", admin, http.MethodPost, userPath(adminID, "/disable?confirm=true"), nil, 409, "invariant_violated"},
		{"delete last admin", admin, http.MethodDelete, userPath(adminID, "?confirm=true"), nil, 409, "invariant_violated"},
		{"demote last admin", admin, http.MethodPut, userPath(adminID, "/roles?confirm=true"), gen.UserRoles{RoleIds: []int64{}}, 409, "invariant_violated"},
	}
	for _, tt := range tests {
		res := tt.c.do(tt.method, tt.path, tt.body)
		if res.Code != tt.status || res.errorCode() != tt.code {
			t.Errorf("%s: %d %s, want %d %s", tt.name, res.Code, res.Body, tt.status, tt.code)
		}
	}
	if d := errorDetails(t, admin.do(http.MethodPost, userPath(adminID, "/disable"), nil)); d["would_lose"] != "account" {
		t.Errorf("would_lose = %v", d["would_lose"])
	}
	// Nothing was changed by any of that.
	mustStatus(t, admin.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	if u, _ := e.user("admin"); u.Disabled {
		t.Error("admin was disabled")
	}
	noSecretsAudited(t, e, "taken-over-pw", "long-enough-pw")
}

// TestUserSelfChanges: changes to your own account go ahead once confirmed. Disabling or deleting it ends the session
// and clears the cookie; losing users.manage takes effect at once.
func TestUserSelfChanges(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	twoID := e.addUser("two", "two-password-12", true)
	readerID := e.addRoleUser("reader", "reader-password-1", rbac.DomainsView)
	readerRole := decode[gen.User](t, e.loggedIn("admin", "admin-password-1").do(http.MethodGet, userPath(readerID, ""), nil)).Roles[0].Id

	two := e.loggedIn("two", "two-password-12")
	res := two.do(http.MethodPut, userPath(twoID, "/roles"), gen.UserRoles{RoleIds: []int64{readerRole}})
	if res.Code != http.StatusConflict || res.errorCode() != "confirmation_required" {
		t.Fatalf("demoting yourself: %d %s", res.Code, res.Body)
	}
	if lose := errorDetails(t, res)["would_lose"]; fmt.Sprint(lose) != "[roles.manage users.manage]" {
		t.Errorf("would_lose = %v", lose)
	}
	mustStatus(t, two.do(http.MethodPut, userPath(twoID, "/roles?confirm=true"), gen.UserRoles{RoleIds: []int64{readerRole}}), http.StatusOK)
	// The session is kept, with its new roles.
	mustStatus(t, two.do(http.MethodGet, "/api/v1/users", nil), http.StatusForbidden)

	// Give two the admin role back, then have them delete their own account.
	admin := e.loggedIn("admin", "admin-password-1")
	mustStatus(t, admin.do(http.MethodPut, userPath(twoID, "/roles"), gen.UserRoles{RoleIds: []int64{adminRoleID}}), http.StatusOK)
	two = e.loggedIn("two", "two-password-12")
	res = two.do(http.MethodDelete, userPath(twoID, "?confirm=true"), nil)
	mustStatus(t, res, http.StatusNoContent)
	if ck := res.cookie(auth.SessionCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("session cookie not cleared: %+v", ck)
	}
	mustStatus(t, two.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	if _, ok := e.user("two"); ok {
		t.Error("two still exists")
	}
	// The audit row survives the user it was about.
	if !slices.Contains(e.auditActions(), "user_delete") {
		t.Errorf("no user_delete row: %v", e.auditActions())
	}
}

func TestChangeOwnPassword(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	const next = "alice-password-2"

	here := e.loggedIn("alice", "alice-password-1")
	there := e.loggedIn("alice", "alice-password-1")
	change := func(c *client, current, new string) response {
		return c.do(http.MethodPost, "/api/v1/auth/password", gen.PasswordChange{CurrentPassword: current, NewPassword: new})
	}

	tests := []struct {
		name, current, new string
		status             int
		code, field        string
	}{
		{"wrong current", "not-my-password", next, 401, "invalid_credentials", ""},
		{"too short", "alice-password-1", "short", 400, "validation_failed", "new_password"},
		{"same as before", "alice-password-1", "alice-password-1", 400, "validation_failed", "new_password"},
		{"empty", "", next, 400, "validation_failed", "new_password"},
	}
	for _, tt := range tests {
		res := change(here, tt.current, tt.new)
		if res.Code != tt.status || res.errorCode() != tt.code {
			t.Errorf("%s: %d %s", tt.name, res.Code, res.Body)
		}
		if tt.field != "" && errorDetails(t, res)["field"] != tt.field {
			t.Errorf("%s: details %s", tt.name, res.Body)
		}
	}
	// A wrong current password doesn't end the session.
	mustStatus(t, here.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	mustStatus(t, change(here, "alice-password-1", next), http.StatusNoContent)
	mustStatus(t, here.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	if res := e.client("10.0.0.5:1").login("alice", "alice-password-1"); res.Code != http.StatusUnauthorized {
		t.Errorf("old password: %d", res.Code)
	}
	e.loggedIn("alice", next)

	var ok, failed int
	for _, r := range e.auditRows() {
		if r.Action != "password_change" {
			continue
		}
		if r.Result == "success" {
			ok++
			if !strings.Contains(r.Detail, `"sessions_ended":1`) || r.Target != "user:alice" {
				t.Errorf("success row: %+v", r)
			}
		} else {
			failed++
		}
	}
	if ok != 1 || failed != 1 {
		t.Errorf("password_change rows: %d successes, %d failures; want 1 and 1", ok, failed)
	}
	noSecretsAudited(t, e, "alice-password-1", next, "not-my-password")
}

// TestChangeOwnPasswordRateLimited: wrong current passwords count against the login limits, in both directions.
func TestChangeOwnPasswordRateLimited(t *testing.T) {
	e := newTestEnv(t, withLimits) // 3 failures per username
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	c := e.loggedIn("alice", "alice-password-1")
	change := func(current string) response {
		return c.do(http.MethodPost, "/api/v1/auth/password", gen.PasswordChange{CurrentPassword: current, NewPassword: "alice-password-2"})
	}

	e.client("10.0.0.7:1").login("alice", "wrong") // one failed login
	change("wrong-1")
	before := len(e.auditRows())
	if res := change("wrong-2"); res.Code != http.StatusUnauthorized {
		t.Fatalf("third failure: %d", res.Code)
	}
	if rows := e.auditRows(); len(rows) != before+1 || !strings.Contains(rows[len(rows)-1].Detail, "locked_out") {
		t.Errorf("the failure that tripped the limit isn't marked locked_out: %+v", rows[len(rows)-1])
	}

	// Now even the right password is refused, here and on the login page.
	res := change("alice-password-1")
	if res.Code != http.StatusTooManyRequests || res.errorCode() != "rate_limited" || res.Header().Get("Retry-After") == "" {
		t.Errorf("limited change: %d %s", res.Code, res.Body)
	}
	if res := e.client("10.0.0.8:1").login("alice", "alice-password-1"); res.Code != http.StatusTooManyRequests {
		t.Errorf("limited login: %d", res.Code)
	}
}

func TestChangeOwnPasswordLDAP(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir)
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("dana", "dana-password")
	res := c.do(http.MethodPost, "/api/v1/auth/password", gen.PasswordChange{CurrentPassword: "dana-password", NewPassword: "new-password-12"})
	if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" || !strings.Contains(res.Body.String(), "directory") {
		t.Errorf("LDAP user: %d %s", res.Code, res.Body)
	}
}
