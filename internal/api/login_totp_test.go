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
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
)

// totpUser makes a local user with a role and two-factor login on, and returns their ID, authenticator and
// recovery codes. The session used to set it up is logged out again.
func totpUser(t *testing.T, e *testEnv, clock *totpClock, name, password string) (int64, authenticator, []string) {
	t.Helper()
	id := e.addRoleUser(name, password, rbac.DomainsView)
	c := e.loggedIn(name, password)
	app, codes := enableTOTP(t, c, clock)
	mustStatus(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
	return id, app, codes
}

func loginRows(e *testEnv) (ok, failed []db.AuditLog) {
	for _, r := range e.auditRows() {
		if r.Action != "login" {
			continue
		}
		if r.Result == "success" {
			ok = append(ok, r)
		} else {
			failed = append(failed, r)
		}
	}
	return ok, failed
}

// TestLoginWithTOTP: the password alone gives a user with two-factor login no session and no audit row; a wrong code
// is refused and audited; the right one finishes the login as a password does for anyone else; and a code that
// logged someone in can't do it again.
func TestLoginWithTOTP(t *testing.T) {
	e, clock := newTOTPEnv(t)
	aliceID, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	okBefore, _ := loginRows(e)

	c := e.client("10.0.0.1:1")
	res := c.login(" Alice ", "alice-password-1")
	if res.Code != http.StatusAccepted || !decode[gen.LoginPending](t, res).TotpRequired {
		t.Fatalf("password step: %d %s", res.Code, res.Body)
	}
	if res.cookie(auth.SessionCookie) != nil || c.cookies[auth.SessionCookie] != nil {
		t.Fatal("the password step set a session cookie")
	}
	if got := c.do(http.MethodGet, "/api/v1/auth/session", nil); got.Code != http.StatusUnauthorized {
		t.Fatalf("a session exists after the password step: %d", got.Code)
	}
	if ok, failed := loginRows(e); len(ok) != len(okBefore) || len(failed) != 0 {
		t.Errorf("the password step was audited: %d successes, %d failures", len(ok)-len(okBefore), len(failed))
	}
	if n := len(mustSessions(t, e, aliceID)); n != 0 {
		t.Errorf("%d sessions in the database after the password step", n)
	}

	for name, code := range map[string]string{"a wrong code": wrongCode(app.code()), "letters": "abcdef"} {
		res := c.loginTOTP(code)
		if res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" || res.cookie(auth.SessionCookie) != nil {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	if res := c.loginTOTP(""); res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
		t.Errorf("an empty code: %d %s", res.Code, res.Body)
	}

	code := app.code()
	res = c.loginTOTP(code[:3] + " " + code[3:])
	mustStatus(t, res, http.StatusOK)
	s := decode[gen.CurrentSession](t, res)
	if s.User.Username != "alice" || s.User.Id != aliceID || s.User.Source != "local" || s.CsrfToken == "" || len(s.PublicId) != 22 {
		t.Errorf("session = %+v", s)
	}
	ck := res.cookie(auth.SessionCookie)
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", ck)
	}
	mustStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	// The pending login is used up: the same browser can't finish it twice.
	clock.nextStep()
	if res := e.client("10.0.0.1:1").loginTOTP(app.code()); res.Code != http.StatusForbidden {
		t.Errorf("a browser with no cookie at all: %d %s", res.Code, res.Body) // no anonymous cookie, so no CSRF token
	}

	// The code that logged alice in is spent, though its 30 seconds may not be over.
	clock.at = clock.at.Add(-totp.Period)
	again := e.client("10.0.0.2:1")
	mustStatus(t, again.login("alice", "alice-password-1"), http.StatusAccepted)
	if res := again.loginTOTP(code); res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
		t.Errorf("a code used for a login, again: %d %s", res.Code, res.Body)
	}
	clock.nextStep()
	mustStatus(t, again.loginTOTP(app.code()), http.StatusOK)

	ok, failed := loginRows(e)
	if len(ok) != len(okBefore)+2 || len(failed) != 3 {
		t.Fatalf("login rows: %d new successes, %d failures; want 2 and 3", len(ok)-len(okBefore), len(failed))
	}
	last := ok[len(ok)-1]
	if last.UserID.Int64 != aliceID || last.Username != "alice" || !strings.Contains(last.Detail, `"method":"local"`) ||
		!strings.Contains(last.Detail, `"second_factor":"code"`) || !strings.Contains(last.Detail, `"session":`) {
		t.Errorf("success row: %+v", last)
	}
	for _, r := range failed {
		if r.Username != "alice" || !strings.Contains(r.Detail, "totp_invalid") || strings.Contains(r.Detail, "session") {
			t.Errorf("failure row: %+v", r)
		}
	}
	noSecretsAudited(t, e, "alice-password-1", code, totp.Encode(app.secret))
}

func mustSessions(t *testing.T, e *testEnv, userID int64) []db.Session {
	t.Helper()
	rows, err := e.st.Read().ListUserSessions(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestLoginWithRecoveryCode: a recovery code stands in for a six-digit code once, and its use is audited.
func TestLoginWithRecoveryCode(t *testing.T) {
	e, clock := newTOTPEnv(t)
	aliceID, _, codes := totpUser(t, e, clock, "alice", "alice-password-1")

	c := e.client("10.0.0.1:1")
	mustStatus(t, c.login("alice", "alice-password-1"), http.StatusAccepted)
	mustStatus(t, c.loginTOTP(strings.ToUpper(codes[2])), http.StatusOK)
	if st := totpStatus(t, c); st.RecoveryCodesLeft != totp.RecoveryCodeCount-1 {
		t.Errorf("codes left: %d", st.RecoveryCodesLeft)
	}

	again := e.client("10.0.0.2:1")
	mustStatus(t, again.login("alice", "alice-password-1"), http.StatusAccepted)
	if res := again.loginTOTP(codes[2]); res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
		t.Errorf("a recovery code used twice: %d %s", res.Code, res.Body)
	}
	mustStatus(t, again.loginTOTP(codes[3]), http.StatusOK)

	var used []db.AuditLog
	for _, r := range e.auditRows() {
		if r.Action == "recovery_code_used" {
			used = append(used, r)
		}
	}
	if len(used) != 2 || used[0].UserID.Int64 != aliceID || used[0].Target != "user:alice" ||
		!strings.Contains(used[0].Detail, `"left":9`) || !strings.Contains(used[1].Detail, `"left":8`) {
		t.Errorf("recovery_code_used rows: %+v", used)
	}
	ok, _ := loginRows(e)
	if last := ok[len(ok)-1]; !strings.Contains(last.Detail, `"second_factor":"recovery_code"`) {
		t.Errorf("login row: %+v", last)
	}
	noSecretsAudited(t, e, codes...)
}

// TestPendingLoginBelongsToTheBrowser: the second step only works from the browser that sent the password, within 5
// minutes, and for 5 wrong codes. After that the password is needed again.
func TestPendingLoginBelongsToTheBrowser(t *testing.T) {
	e, clock := newTOTPEnv(t)
	_, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	wall := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	e.srv.pending.now = func() time.Time { return wall }
	expired := func(when string, res response) {
		t.Helper()
		if res.Code != http.StatusUnauthorized || res.errorCode() != "login_expired" || res.cookie(auth.SessionCookie) != nil {
			t.Errorf("%s: %d %s", when, res.Code, res.Body)
		}
	}

	// No password first.
	stranger := e.client("10.0.0.3:1")
	stranger.fetchCSRF()
	expired("a code with no password before it", stranger.loginTOTP(app.code()))

	// Someone who knows a code, in another browser, can't finish alice's login.
	alice := e.client("10.0.0.1:1")
	mustStatus(t, alice.login("alice", "alice-password-1"), http.StatusAccepted)
	expired("another browser", stranger.loginTOTP(app.code()))
	// Nor can they with alice's anonymous cookie but no pending login of their own after it has been finished.
	mustStatus(t, alice.loginTOTP(app.code()), http.StatusOK)
	clock.nextStep()
	mustStatus(t, alice.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
	alice.csrf = ""
	alice.fetchCSRF()
	expired("a finished login, again", alice.loginTOTP(app.code()))

	// Out of time: one second short still works, 5 minutes doesn't.
	mustStatus(t, alice.login("alice", "alice-password-1"), http.StatusAccepted)
	wall = wall.Add(pendingLoginTTL - time.Second)
	if res := alice.loginTOTP(wrongCode(app.code())); res.errorCode() != "totp_invalid" {
		t.Errorf("just inside the time: %d %s", res.Code, res.Body)
	}
	wall = wall.Add(time.Second)
	expired("after 5 minutes", alice.loginTOTP(app.code()))

	// Out of attempts: the fifth wrong code ends it, and then even the right code needs the password again.
	mustStatus(t, alice.login("alice", "alice-password-1"), http.StatusAccepted)
	for i := 1; i <= pendingLoginAttempts; i++ {
		if res := alice.loginTOTP(wrongCode(app.code())); res.errorCode() != "totp_invalid" {
			t.Fatalf("wrong code %d: %d %s", i, res.Code, res.Body)
		}
	}
	expired("after 5 wrong codes", alice.loginTOTP(app.code()))
	rows := e.auditRows()
	if last := rows[len(rows)-1]; last.Action != "login" || !strings.Contains(last.Detail, `"attempts_used":5`) {
		t.Errorf("the last wrong code's row: %+v", last)
	}

	// A new password login replaces the browser's pending login rather than adding to it.
	mustStatus(t, alice.login("alice", "alice-password-1"), http.StatusAccepted)
	mustStatus(t, alice.login("alice", "alice-password-1"), http.StatusAccepted)
	if n := len(e.srv.pending.m); n != 1 {
		t.Errorf("%d pending logins for one browser", n)
	}
	mustStatus(t, alice.loginTOTP(app.code()), http.StatusOK)
	if n := len(e.srv.pending.m); n != 0 {
		t.Errorf("%d pending logins after finishing", n)
	}
}

// TestLoginTOTPNeedsCSRF: the second step is a state-changing request like the first.
func TestLoginTOTPNeedsCSRF(t *testing.T) {
	e, clock := newTOTPEnv(t)
	_, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	c := e.client("10.0.0.1:1")
	mustStatus(t, c.login("alice", "alice-password-1"), http.StatusAccepted)

	req := c.request(http.MethodPost, "/api/v1/auth/login/totp", gen.TOTPCode{Code: app.code()})
	req.Header.Del("X-CSRF-Token")
	if res := c.send(req); res.Code != http.StatusForbidden || res.errorCode() != "csrf_failed" {
		t.Errorf("without a CSRF token: %d %s", res.Code, res.Body)
	}
	req = c.request(http.MethodPost, "/api/v1/auth/login/totp", gen.TOTPCode{Code: app.code()})
	req.Header.Set("Origin", "https://evil.example")
	if res := c.send(req); res.Code != http.StatusForbidden || res.errorCode() != "csrf_failed" {
		t.Errorf("from another origin: %d %s", res.Code, res.Body)
	}
	// Neither spent the code or the pending login.
	mustStatus(t, c.loginTOTP(app.code()), http.StatusOK)
}

// TestLoginTOTPRateLimited: wrong codes count against the same limits as wrong passwords, a correct password doesn't
// clear the username's count, and a finished login does.
func TestLoginTOTPRateLimited(t *testing.T) {
	e, clock := newTOTPEnv(t, withLimits) // 4 failures per address, 3 per username
	_, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	browser := func(i int) *client { return e.client(fmt.Sprintf("10.0.1.%d:1", i)) }

	// Two wrong passwords, then the right one: the count isn't cleared by it.
	browser(1).login("alice", "wrong-1")
	browser(2).login("alice", "wrong-2")
	c := browser(3)
	mustStatus(t, c.login("alice", "alice-password-1"), http.StatusAccepted)
	before := len(e.auditRows())
	if res := c.loginTOTP(wrongCode(app.code())); res.errorCode() != "totp_invalid" {
		t.Fatalf("third failure: %d %s", res.Code, res.Body)
	}
	if rows := e.auditRows(); len(rows) != before+1 || !strings.Contains(rows[len(rows)-1].Detail, `"locked_out":"username"`) {
		t.Errorf("the wrong code that tripped the limit isn't marked locked_out: %+v", rows[len(rows)-1])
	}
	// Locked: the right code is refused without being checked, and so is the password elsewhere.
	res := c.loginTOTP(app.code())
	if res.Code != http.StatusTooManyRequests || res.errorCode() != "rate_limited" || res.Header().Get("Retry-After") == "" {
		t.Errorf("limited code: %d %s", res.Code, res.Body)
	}
	if res := browser(4).login("alice", "alice-password-1"); res.Code != http.StatusTooManyRequests {
		t.Errorf("limited password: %d", res.Code)
	}
	if n := len(e.auditRows()); n != before+1 {
		t.Errorf("refused attempts were audited: %d rows", n-before-1)
	}

	// Wrong codes count against the address too, whoever they are for.
	e2, clock2 := newTOTPEnv(t, withLimits)
	apps := map[string]authenticator{}
	for _, name := range []string{"bob", "carol"} {
		_, apps[name], _ = totpUser(t, e2, clock2, name, name+"-password-12")
	}
	shared := e2.client("10.0.2.9:1")
	for i, name := range []string{"bob", "bob", "carol", "carol"} {
		mustStatus(t, shared.login(name, name+"-password-12"), http.StatusAccepted)
		if res := shared.loginTOTP(wrongCode(apps[name].code())); res.errorCode() != "totp_invalid" {
			t.Fatalf("failure %d from one address: %d %s", i+1, res.Code, res.Body)
		}
	}
	if res := shared.login("carol", "carol-password-12"); res.Code != http.StatusTooManyRequests {
		t.Errorf("the address after 4 wrong codes: %d", res.Code)
	}

	// A finished login clears the username's count.
	e3, clock3 := newTOTPEnv(t, withLimits)
	_, app3, _ := totpUser(t, e3, clock3, "dave", "dave-password-123")
	for i := 1; i <= 2; i++ {
		e3.client(fmt.Sprintf("10.0.3.%d:1", i)).login("dave", "wrong")
	}
	d := e3.client("10.0.3.3:1")
	mustStatus(t, d.login("dave", "dave-password-123"), http.StatusAccepted)
	mustStatus(t, d.loginTOTP(app3.code()), http.StatusOK)
	clock3.nextStep()
	for i := 4; i <= 5; i++ {
		e3.client(fmt.Sprintf("10.0.3.%d:1", i)).login("dave", "wrong")
	}
	if res := e3.client("10.0.3.6:1").login("dave", "dave-password-123"); res.Code != http.StatusAccepted {
		t.Errorf("after a finished login and two more failures: %d %s", res.Code, res.Body)
	}
}

// TestLoginTOTPChecksTheAccountAgain: what changed between the password and the code counts. A disabled account
// can't finish, a user who lost their roles has no access, and one whose two-factor login was removed starts again
// with the password alone.
func TestLoginTOTPChecksTheAccountAgain(t *testing.T) {
	ctx := context.Background()
	e, clock := newTOTPEnv(t)
	aliceID, alice, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	bobID, bob, _ := totpUser(t, e, clock, "bob", "bob-password-123")
	carolID, carol, _ := totpUser(t, e, clock, "carol", "carol-password-1")
	change := func(fn func(q *db.Queries) error) {
		t.Helper()
		if err := e.st.WithTx(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}

	a := e.client("10.0.0.1:1")
	mustStatus(t, a.login("alice", "alice-password-1"), http.StatusAccepted)
	change(func(q *db.Queries) error {
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: true, ID: aliceID})
	})
	if res := a.loginTOTP(alice.code()); res.Code != http.StatusUnauthorized || res.errorCode() != "invalid_credentials" {
		t.Errorf("disabled since the password: %d %s", res.Code, res.Body)
	}
	// The pending login is gone, so enabling the account again doesn't revive it.
	change(func(q *db.Queries) error {
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: false, ID: aliceID})
	})
	if res := a.loginTOTP(alice.code()); res.errorCode() != "login_expired" {
		t.Errorf("after the refusal: %d %s", res.Code, res.Body)
	}

	b := e.client("10.0.0.2:1")
	mustStatus(t, b.login("bob", "bob-password-123"), http.StatusAccepted)
	change(func(q *db.Queries) error { return q.DeleteUserRoles(ctx, bobID) })
	if res := b.loginTOTP(bob.code()); res.Code != http.StatusForbidden || res.errorCode() != "no_access" {
		t.Errorf("no roles since the password: %d %s", res.Code, res.Body)
	}
	// The refusal rolled back with the rest, so the code wasn't spent by it.
	row, err := e.st.Read().GetUserTOTP(ctx, bobID)
	if err != nil || row.LastStep >= totp.Step(clock.at) {
		t.Errorf("bob's last step after a refused login: %d, %v", row.LastStep, err)
	}

	c := e.client("10.0.0.3:1")
	mustStatus(t, c.login("carol", "carol-password-1"), http.StatusAccepted)
	change(func(q *db.Queries) error { _, err := q.DeleteUserTOTP(ctx, carolID); return err })
	if res := c.loginTOTP(carol.code()); res.Code != http.StatusUnauthorized || res.errorCode() != "login_expired" {
		t.Errorf("two-factor login removed since the password: %d %s", res.Code, res.Body)
	}
	mustStatus(t, c.login("carol", "carol-password-1"), http.StatusOK)

	_, failed := loginRows(e)
	var disabled, noAccess int
	for _, r := range failed {
		switch {
		case strings.Contains(r.Detail, "account disabled"):
			disabled++
		case strings.Contains(r.Detail, "not authorised"):
			noAccess++
		}
	}
	if disabled != 1 || noAccess != 1 {
		t.Errorf("failure rows: %d disabled, %d no access; want 1 and 1: %+v", disabled, noAccess, failed)
	}
}

// TestLoginTOTPReplacesSessionAtTheEnd: a browser that is logged in keeps that session through the password step,
// and loses it only when the new login is finished.
func TestLoginTOTPReplacesSessionAtTheEnd(t *testing.T) {
	e, clock := newTOTPEnv(t)
	_, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)

	c := e.loggedIn("bob", "bob-password-123")
	old := *c.cookies[auth.SessionCookie]
	mustStatus(t, c.login("alice", "alice-password-1"), http.StatusAccepted)
	res := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	if res.Code != http.StatusOK || decode[gen.CurrentSession](t, res).User.Username != "bob" {
		t.Fatalf("bob's session after alice's password: %d %s", res.Code, res.Body)
	}
	mustStatus(t, c.loginTOTP(app.code()), http.StatusOK)
	res = c.do(http.MethodGet, "/api/v1/auth/session", nil)
	if res.Code != http.StatusOK || decode[gen.CurrentSession](t, res).User.Username != "alice" {
		t.Errorf("the session after the code: %d %s", res.Code, res.Body)
	}
	stale := c.request(http.MethodGet, "/api/v1/auth/session", nil)
	stale.Header.Del("Cookie")
	stale.AddCookie(&old)
	if got := c.send(stale); got.Code != http.StatusUnauthorized {
		t.Errorf("bob's old session still works: %d", got.Code)
	}
}

// TestLoginWithTOTPLDAP: an LDAP user's second step works the same, and their roles come from the directory groups
// the password step found.
func TestLoginWithTOTPLDAP(t *testing.T) {
	clock := &totpClock{at: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir, withTOTP(clock))
	e.addUser("admin", "admin-password-1", true)
	first := e.loggedIn("dana", "dana-password")
	app, _ := enableTOTP(t, first, clock)

	c := e.client("10.0.0.4:1")
	mustStatus(t, c.login("dana", "dana-password"), http.StatusAccepted)
	res := c.loginTOTP(app.code())
	mustStatus(t, res, http.StatusOK)
	s := decode[gen.CurrentSession](t, res)
	if s.User.Username != "dana" || s.User.Source != "ldap" || len(s.Permissions.Global) == 0 {
		t.Errorf("session = %+v", s)
	}
	ok, _ := loginRows(e)
	if last := ok[len(ok)-1]; !strings.Contains(last.Detail, `"method":"ldap"`) || !strings.Contains(last.Detail, `"second_factor":"code"`) {
		t.Errorf("login row: %+v", last)
	}

	// Taken out of the group between the password and the code: no access, with the groups in the audit row.
	clock.nextStep()
	d := e.client("10.0.0.5:1")
	mustStatus(t, d.login("dana", "dana-password"), http.StatusAccepted)
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		mappings, err := q.ListAllLDAPMappings(ctx)
		if err != nil {
			return err
		}
		for _, m := range mappings {
			if err := q.DeleteLDAPMapping(ctx, m.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if res := d.loginTOTP(app.code()); res.Code != http.StatusForbidden || res.errorCode() != "no_access" {
		t.Errorf("unmapped since the password: %d %s", res.Code, res.Body)
	}
	_, failed := loginRows(e)
	if len(failed) != 1 || !strings.Contains(failed[0].Detail, "CN=Dana,DC=example,DC=local") || !strings.Contains(failed[0].Detail, "groups") {
		t.Errorf("the no-access row: %+v", failed)
	}
}

// TestPendingLoginsCap: the map can't grow past its cap, and the oldest goes first.
func TestPendingLoginsCap(t *testing.T) {
	p := newPendingLogins()
	at := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return at }
	key := func(i int) []byte { return []byte(fmt.Sprintf("browser-%05d", i)) }
	id := &auth.Identity{Username: "alice", Source: auth.MethodLocal}
	for i := 0; i < maxPendingLogins; i++ {
		p.put(key(i), id, 1)
		at = at.Add(time.Millisecond)
	}
	p.put(key(maxPendingLogins), id, 1)
	if len(p.m) != maxPendingLogins {
		t.Fatalf("%d pending logins, want the cap of %d", len(p.m), maxPendingLogins)
	}
	if _, ok := p.get(key(0)); ok {
		t.Error("the oldest wasn't the one dropped")
	}
	if _, ok := p.get(key(1)); !ok {
		t.Error("the second oldest was dropped")
	}
	// Replacing one's own doesn't push anyone out.
	p.put(key(1), id, 1)
	if _, ok := p.get(key(2)); !ok || len(p.m) != maxPendingLogins {
		t.Errorf("replacing a pending login dropped another (%d left)", len(p.m))
	}
	// Those out of time are swept when the next one arrives.
	at = at.Add(pendingLoginTTL)
	p.put(key(-1), id, 1)
	if len(p.m) != 1 {
		t.Errorf("%d pending logins after all but one ran out of time", len(p.m))
	}
}
