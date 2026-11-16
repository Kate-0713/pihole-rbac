// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
)

const totpBase = "/api/v1/auth/totp"

// totpClock is the time the two-factor service sees, which tests move to get the next code.
type totpClock struct{ at time.Time }

func (c *totpClock) now() time.Time { return c.at }

// nextStep moves on one 30-second step, so the next code is a new one.
func (c *totpClock) nextStep() { c.at = c.at.Add(totp.Period) }

// withTOTP gives the server a two-factor service with a master key and a clock the test controls.
func withTOTP(clock *totpClock) func(*Options) {
	return func(o *Options) {
		c, err := secrets.NewCipher(bytes.Repeat([]byte{7}, secrets.KeySize))
		if err != nil {
			panic(err)
		}
		o.TOTP = &totp.Service{Store: o.Store, Audit: o.Audit, Cipher: func() *secrets.Cipher { return c }, Now: clock.now}
	}
}

func newTOTPEnv(t *testing.T, modify ...func(*Options)) (*testEnv, *totpClock) {
	t.Helper()
	clock := &totpClock{at: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	return newTestEnv(t, append([]func(*Options){withTOTP(clock)}, modify...)...), clock
}

// authenticator is an authenticator app: it holds the secret that setup returned and makes codes from it.
type authenticator struct {
	secret secrets.Value
	clock  *totpClock
}

func (a authenticator) code() string { return totp.Code(a.secret, a.clock.at) }

// setupTOTP starts setup for c and returns an authenticator holding the new secret.
func setupTOTP(t *testing.T, c *client, clock *totpClock) (authenticator, gen.TOTPEnrolment) {
	t.Helper()
	res := c.do(http.MethodPost, totpBase+"/setup", nil)
	mustStatus(t, res, http.StatusOK)
	e := decode[gen.TOTPEnrolment](t, res)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Secret)
	if err != nil || len(raw) != totp.SecretSize {
		t.Fatalf("secret %q: %v", e.Secret, err)
	}
	return authenticator{secret: secrets.NewValue(raw), clock: clock}, e
}

// enableTOTP sets two-factor login up for c and turns it on, returning the authenticator and the recovery codes.
func enableTOTP(t *testing.T, c *client, clock *totpClock) (authenticator, []string) {
	t.Helper()
	app, _ := setupTOTP(t, c, clock)
	res := c.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: app.code()})
	mustStatus(t, res, http.StatusOK)
	clock.nextStep() // the code that confirmed is spent
	return app, decode[gen.RecoveryCodes](t, res).RecoveryCodes
}

func totpStatus(t *testing.T, c *client) gen.TOTPStatus {
	t.Helper()
	res := c.do(http.MethodGet, totpBase, nil)
	mustStatus(t, res, http.StatusOK)
	return decode[gen.TOTPStatus](t, res)
}

func auditCount(e *testEnv, action, result string) int {
	n := 0
	for _, r := range e.auditRows() {
		if r.Action == action && r.Result == result {
			n++
		}
	}
	return n
}

// TestTOTPSetupAndConfirm: setup returns the secret three ways and changes nothing until a code is confirmed; a
// wrong code is refused; confirming turns it on, returns ten recovery codes, ends the user's other sessions and is
// audited without the secret or a code.
func TestTOTPSetupAndConfirm(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	here := e.loggedIn("alice", "alice-password-1")
	there := e.loggedIn("alice", "alice-password-1")

	if st := totpStatus(t, here); !st.Available || st.Enabled || st.Pending || st.Required || st.RecoveryCodesLeft != 0 || st.EnabledAt != nil {
		t.Fatalf("before setup: %+v", st)
	}
	// Nothing to confirm yet.
	res := here.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: "123456"})
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "not_pending" {
		t.Errorf("confirm before setup: %d %s", res.Code, res.Body)
	}

	first, _ := setupTOTP(t, here, clock)
	app, enrol := setupTOTP(t, here, clock) // asking again replaces the secret that was never confirmed
	if first.secret.Equal(app.secret) {
		t.Fatal("setup returned the same secret twice")
	}
	u, err := url.Parse(enrol.Uri)
	if err != nil || u.Scheme != "otpauth" || u.Path != "/pihole-rbac:alice" || u.Query().Get("secret") != enrol.Secret {
		t.Errorf("uri = %q, %v", enrol.Uri, err)
	}
	if !strings.HasPrefix(enrol.Qr, "data:image/svg+xml;base64,") {
		t.Errorf("qr = %.40q", enrol.Qr)
	}
	if st := totpStatus(t, here); st.Enabled || !st.Pending {
		t.Errorf("after setup: %+v", st)
	}
	// A secret that isn't confirmed asks nothing of a login.
	e.loggedIn("alice", "alice-password-1")

	for name, code := range map[string]string{
		"the replaced secret's code": first.code(),
		"a wrong code":               wrongCode(app.code()),
		"letters":                    "abcdef",
		"a recovery code's shape":    "abcd-efgh-ijkl-mnop",
	} {
		res := here.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: code})
		if res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	res = here.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: ""})
	if res.Code != http.StatusBadRequest {
		t.Errorf("an empty code: %d %s", res.Code, res.Body)
	}
	// Wrong codes here don't end the session or count against the login limits.
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	code := app.code()
	res = here.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: code[:3] + " " + code[3:]})
	mustStatus(t, res, http.StatusOK)
	codes := decode[gen.RecoveryCodes](t, res).RecoveryCodes
	if len(codes) != totp.RecoveryCodeCount {
		t.Fatalf("%d recovery codes", len(codes))
	}
	st := totpStatus(t, here)
	if !st.Enabled || st.Pending || st.RecoveryCodesLeft != totp.RecoveryCodeCount || st.EnabledAt == nil || !st.EnabledAt.Equal(clock.at) {
		t.Errorf("after confirming: %+v", st)
	}
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)

	// On already: neither setup nor confirm does anything.
	res = here.do(http.MethodPost, totpBase+"/setup", nil)
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "enabled" {
		t.Errorf("setup while on: %d %s", res.Code, res.Body)
	}
	clock.nextStep()
	res = here.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: app.code()})
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "enabled" {
		t.Errorf("confirm while on: %d %s", res.Code, res.Body)
	}
	if st := totpStatus(t, here); st.RecoveryCodesLeft != totp.RecoveryCodeCount {
		t.Errorf("recovery codes after a refused confirm: %d", st.RecoveryCodesLeft)
	}

	if n := auditCount(e, "totp_enable", "success"); n != 1 {
		t.Errorf("%d totp_enable rows, want 1", n)
	}
	rows := e.auditRows()
	last := rows[len(rows)-1]
	if last.Action != "totp_enable" || last.Target != "user:alice" || !strings.Contains(last.Detail, `"sessions_ended":2`) {
		t.Errorf("audit row: %+v", last)
	}
	noSecretsAudited(t, e, append(codes, enrol.Secret, first.code(), code, enrol.Uri)...)
}

// wrongCode returns six digits that aren't the code given, nor likely its neighbours'.
func wrongCode(code string) string {
	b := []byte(code)
	for i := range b {
		b[i] = '0' + (b[i]-'0'+5)%10
	}
	return string(b)
}

// TestTOTPUnavailable: without a master key the secret can't be stored, and the status says so.
func TestTOTPUnavailable(t *testing.T) {
	e := newTestEnv(t, func(o *Options) {
		o.TOTP = &totp.Service{Store: o.Store, Audit: o.Audit, Cipher: o.Secrets.Cipher}
	})
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	c := e.loggedIn("alice", "alice-password-1")
	if st := totpStatus(t, c); st.Available {
		t.Errorf("status without a master key: %+v", st)
	}
	res := c.do(http.MethodPost, totpBase+"/setup", nil)
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "no_master_key" {
		t.Errorf("setup without a master key: %d %s", res.Code, res.Body)
	}
}

// TestTOTPNeedsSessionAndCSRF: the routes are for a logged-in user, and the writes need the CSRF token.
func TestTOTPNeedsSessionAndCSRF(t *testing.T) {
	e, _ := newTOTPEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	anon := e.client("10.0.0.9:1")
	anon.fetchCSRF()
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, totpBase}, {http.MethodPost, totpBase + "/setup"}, {http.MethodPost, totpBase + "/confirm"},
		{http.MethodPost, totpBase + "/disable"}, {http.MethodPost, totpBase + "/recovery-codes"},
	} {
		if res := anon.do(r.method, r.path, gen.TOTPCode{Code: "123456"}); res.Code != http.StatusUnauthorized || res.errorCode() != "unauthenticated" {
			t.Errorf("%s %s without a session: %d %s", r.method, r.path, res.Code, res.Body)
		}
	}
	c := e.loggedIn("alice", "alice-password-1")
	req := c.request(http.MethodPost, totpBase+"/setup", nil)
	req.Header.Del("X-CSRF-Token")
	if res := c.send(req); res.Code != http.StatusForbidden || res.errorCode() != "csrf_failed" {
		t.Errorf("setup without a CSRF token: %d %s", res.Code, res.Body)
	}
	if st := totpStatus(t, c); st.Pending {
		t.Error("a request without a CSRF token made a secret")
	}
}

// TestTOTPDisable: turning it off needs the password and a code, each refused when wrong without touching anything;
// a code can't be used twice; a recovery code works once; success removes the secret and codes, ends the other
// sessions and is audited.
func TestTOTPDisable(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)
	here := e.loggedIn("alice", "alice-password-1")
	disable := func(c *client, password, code string) response {
		return c.do(http.MethodPost, totpBase+"/disable", gen.TOTPDisable{Password: password, Code: code})
	}

	// Off: nothing to turn off, whatever is sent.
	res := disable(here, "alice-password-1", "123456")
	if res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "not_enabled" {
		t.Errorf("disable while off: %d %s", res.Code, res.Body)
	}

	app, codes := enableTOTP(t, here, clock)
	there := e.loggedIn("alice", "alice-password-1")
	bob := e.loggedIn("bob", "bob-password-123")
	_, bobCodes := enableTOTP(t, bob, clock)

	for _, tt := range []struct {
		name, password, code string
		status               int
		errCode              string
	}{
		{"a wrong password", "not-my-password", app.code(), 401, "invalid_credentials"},
		{"someone else's password", "bob-password-123", app.code(), 401, "invalid_credentials"},
		{"a wrong code", "alice-password-1", wrongCode(app.code()), 401, "totp_invalid"},
		{"someone else's recovery code", "alice-password-1", bobCodes[0], 401, "totp_invalid"},
		{"no password", "", app.code(), 400, "validation_failed"},
		{"no code", "alice-password-1", "", 400, "validation_failed"},
	} {
		res := disable(here, tt.password, tt.code)
		if res.Code != tt.status || res.errorCode() != tt.errCode {
			t.Errorf("%s: %d %s", tt.name, res.Code, res.Body)
		}
	}
	// A wrong password is refused before the code is looked at, so the code isn't spent by it.
	if st := totpStatus(t, here); !st.Enabled || st.RecoveryCodesLeft != totp.RecoveryCodeCount {
		t.Fatalf("after refused attempts: %+v", st)
	}
	if st := totpStatus(t, bob); st.RecoveryCodesLeft != totp.RecoveryCodeCount {
		t.Errorf("bob's recovery code was spent by alice: %d left", st.RecoveryCodesLeft)
	}
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	mustStatus(t, disable(here, "alice-password-1", app.code()), http.StatusNoContent)
	if st := totpStatus(t, here); st.Enabled || st.Pending || st.RecoveryCodesLeft != 0 {
		t.Errorf("after turning it off: %+v", st)
	}
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	mustStatus(t, bob.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	// The old recovery codes went with the secret.
	_, newCodes := enableTOTP(t, here, clock)
	if res := disable(here, "alice-password-1", codes[0]); res.Code != http.StatusUnauthorized {
		t.Errorf("a recovery code from before: %d %s", res.Code, res.Body)
	}

	// A recovery code, typed in capitals without hyphens, turns it off, and is audited as used.
	typed := strings.ToUpper(strings.ReplaceAll(newCodes[3], "-", ""))
	mustStatus(t, disable(here, "alice-password-1", typed), http.StatusNoContent)

	if ok, failed := auditCount(e, "totp_disable", "success"), auditCount(e, "totp_disable", "failure"); ok != 2 || failed != 5 {
		t.Errorf("totp_disable rows: %d successes, %d failures; want 2 and 5", ok, failed)
	}
	if n := auditCount(e, "recovery_code_used", "success"); n != 1 {
		t.Errorf("%d recovery_code_used rows, want 1", n)
	}
	for _, r := range e.auditRows() {
		switch {
		case r.Action == "totp_disable" && r.Result == "success":
			if r.Target != "user:alice" || !strings.Contains(r.Detail, `"by":"self"`) {
				t.Errorf("totp_disable row: %+v", r)
			}
		case r.Action == "recovery_code_used":
			if r.Target != "user:alice" || !strings.Contains(r.Detail, `"left":9`) {
				t.Errorf("recovery_code_used row: %+v", r)
			}
		}
	}
	noSecretsAudited(t, e, append(append(codes, newCodes...), "alice-password-1", "not-my-password", typed, totp.Encode(app.secret))...)
}

// TestTOTPCodeUsedOnce: a six-digit code works once, even for a different operation, and the next step's works.
func TestTOTPCodeUsedOnce(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	c := e.loggedIn("alice", "alice-password-1")
	app, _ := setupTOTP(t, c, clock)
	confirming := app.code()
	mustStatus(t, c.do(http.MethodPost, totpBase+"/confirm", gen.TOTPCode{Code: confirming}), http.StatusOK)

	regenerate := func(code string) response {
		return c.do(http.MethodPost, totpBase+"/recovery-codes", gen.TOTPCode{Code: code})
	}
	// The code that confirmed is spent, though its 30 seconds aren't over.
	if res := regenerate(confirming); res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
		t.Errorf("the confirming code again: %d %s", res.Code, res.Body)
	}
	clock.nextStep()
	code := app.code()
	mustStatus(t, regenerate(code), http.StatusOK)
	if res := regenerate(code); res.Code != http.StatusUnauthorized {
		t.Errorf("a code used twice: %d %s", res.Code, res.Body)
	}
	res := c.do(http.MethodPost, totpBase+"/disable", gen.TOTPDisable{Password: "alice-password-1", Code: code})
	if res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
		t.Errorf("a used code, to turn it off: %d %s", res.Code, res.Body)
	}
	// A clock a step behind is accepted, but not for a step at or before the last one used.
	clock.at = clock.at.Add(2 * totp.Period)
	behind := totp.Code(app.secret, clock.at.Add(-totp.Period))
	mustStatus(t, regenerate(behind), http.StatusOK)
	older := totp.Code(app.secret, clock.at.Add(-totp.Period))
	if res := regenerate(older); res.Code != http.StatusUnauthorized {
		t.Errorf("the previous step's code after it was used: %d", res.Code)
	}
	mustStatus(t, regenerate(app.code()), http.StatusOK)
}

// TestRegenerateRecoveryCodes: new codes replace the old ones, with a six-digit code or one of the current recovery
// codes; with it off there is nothing to replace.
func TestRegenerateRecoveryCodes(t *testing.T) {
	e, clock := newTOTPEnv(t)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	c := e.loggedIn("alice", "alice-password-1")
	regenerate := func(code string) response {
		return c.do(http.MethodPost, totpBase+"/recovery-codes", gen.TOTPCode{Code: code})
	}
	if res := regenerate("123456"); res.Code != http.StatusConflict || errorDetails(t, res)["reason"] != "not_enabled" {
		t.Errorf("while off: %d %s", res.Code, res.Body)
	}
	app, first := enableTOTP(t, c, clock)
	other := e.loggedIn("alice", "alice-password-1")

	if res := regenerate(wrongCode(app.code())); res.Code != http.StatusUnauthorized || res.errorCode() != "totp_invalid" {
		t.Errorf("a wrong code: %d %s", res.Code, res.Body)
	}
	res := regenerate(app.code())
	mustStatus(t, res, http.StatusOK)
	second := decode[gen.RecoveryCodes](t, res).RecoveryCodes
	if len(second) != totp.RecoveryCodeCount || second[0] == first[0] {
		t.Fatalf("new codes: %v", second)
	}
	// Getting new codes isn't a change to how the user logs in, so their other sessions carry on.
	mustStatus(t, other.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	if res := regenerate(first[0]); res.Code != http.StatusUnauthorized {
		t.Errorf("an old recovery code: %d %s", res.Code, res.Body)
	}
	// One of the current recovery codes gets a new set too, and is spent with the rest.
	res = regenerate(second[0])
	mustStatus(t, res, http.StatusOK)
	third := decode[gen.RecoveryCodes](t, res).RecoveryCodes
	if st := totpStatus(t, c); st.RecoveryCodesLeft != totp.RecoveryCodeCount {
		t.Errorf("codes left: %d", st.RecoveryCodesLeft)
	}
	if res := regenerate(second[1]); res.Code != http.StatusUnauthorized {
		t.Errorf("a code from the replaced set: %d", res.Code)
	}
	if ok, failed := auditCount(e, "recovery_codes_regenerate", "success"), auditCount(e, "recovery_codes_regenerate", "failure"); ok != 2 || failed != 3 {
		t.Errorf("recovery_codes_regenerate rows: %d successes, %d failures; want 2 and 3", ok, failed)
	}
	if n := auditCount(e, "recovery_code_used", "success"); n != 1 {
		t.Errorf("%d recovery_code_used rows, want 1", n)
	}
	noSecretsAudited(t, e, append(append(first, second...), third...)...)
}

// TestTOTPRateLimited: wrong passwords and codes when turning it off or getting new codes count against the login
// limits, and a limit that applies refuses even the right ones, here and on the login page.
func TestTOTPRateLimited(t *testing.T) {
	e, clock := newTOTPEnv(t, withLimits) // 3 failures per username
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	c := e.loggedIn("alice", "alice-password-1")
	app, codes := enableTOTP(t, c, clock)
	disable := func(password, code string) response {
		return c.do(http.MethodPost, totpBase+"/disable", gen.TOTPDisable{Password: password, Code: code})
	}

	if res := disable("wrong-password", app.code()); res.Code != http.StatusUnauthorized {
		t.Fatalf("first failure: %d", res.Code)
	}
	if res := c.do(http.MethodPost, totpBase+"/recovery-codes", gen.TOTPCode{Code: wrongCode(app.code())}); res.Code != http.StatusUnauthorized {
		t.Fatalf("second failure: %d", res.Code)
	}
	before := len(e.auditRows())
	if res := disable("alice-password-1", wrongCode(app.code())); res.Code != http.StatusUnauthorized {
		t.Fatalf("third failure: %d", res.Code)
	}
	if rows := e.auditRows(); len(rows) != before+1 || !strings.Contains(rows[len(rows)-1].Detail, "locked_out") {
		t.Errorf("the failure that tripped the limit isn't marked locked_out: %+v", rows[len(rows)-1])
	}

	calls := e.authn.calls
	res := disable("alice-password-1", app.code())
	if res.Code != http.StatusTooManyRequests || res.errorCode() != "rate_limited" || res.Header().Get("Retry-After") == "" {
		t.Errorf("limited disable: %d %s", res.Code, res.Body)
	}
	if e.authn.calls != calls {
		t.Error("the password was checked while the limit applied")
	}
	res = c.do(http.MethodPost, totpBase+"/recovery-codes", gen.TOTPCode{Code: codes[0]})
	if res.Code != http.StatusTooManyRequests {
		t.Errorf("limited regenerate: %d %s", res.Code, res.Body)
	}
	if st := totpStatus(t, c); !st.Enabled || st.RecoveryCodesLeft != totp.RecoveryCodeCount {
		t.Errorf("after limited attempts: %+v", st)
	}
	if res := e.client("10.0.0.8:1").login("alice", "alice-password-1"); res.Code != http.StatusTooManyRequests {
		t.Errorf("limited login: %d", res.Code)
	}
}

// TestTOTPDisableLDAP: an LDAP user's password is checked in the directory, and a local account's password with the
// same username isn't theirs.
func TestTOTPDisableLDAP(t *testing.T) {
	clock := &totpClock{at: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	e := newLDAPEnv(t, dir, withTOTP(clock))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("dana", "dana-password")
	app, _ := enableTOTP(t, c, clock)
	disable := func(password string) response {
		return c.do(http.MethodPost, totpBase+"/disable", gen.TOTPDisable{Password: password, Code: app.code()})
	}
	for _, wrong := range []string{"not-danas-password", "admin-password-1"} {
		if res := disable(wrong); res.Code != http.StatusUnauthorized || res.errorCode() != "invalid_credentials" {
			t.Errorf("password %q: %d %s", wrong, res.Code, res.Body)
		}
	}
	mustStatus(t, disable("dana-password"), http.StatusNoContent)
	if st := totpStatus(t, c); st.Enabled {
		t.Errorf("after turning it off: %+v", st)
	}
	noSecretsAudited(t, e, "dana-password", "not-danas-password")
}

// TestRemoveUserTOTP: an admin removes another user's two-factor login, which ends that user's sessions. It needs
// users.manage and every grant the user has, can't be done to oneself, and leaves a user without it as they are.
func TestRemoveUserTOTP(t *testing.T) {
	e, clock := newTOTPEnv(t)
	adminID := e.addUser("admin", "admin-password-1", true)
	hrID := e.addRoleUser("hr", "hr-password-123", rbac.UsersManage)
	aliceID := e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	hr := e.loggedIn("hr", "hr-password-123")
	alice := e.loggedIn("alice", "alice-password-1")
	enableTOTP(t, admin, clock)
	enableTOTP(t, alice, clock)
	remove := func(c *client, id int64) response { return c.do(http.MethodDelete, userPath(id, "/totp"), nil) }

	list := decode[gen.UserList](t, admin.do(http.MethodGet, "/api/v1/users", nil)).Users
	for name, want := range map[string]bool{"admin": true, "alice": true, "hr": false} {
		if got := userNamed(t, list, name).TotpEnabled; got != want {
			t.Errorf("%s: totp_enabled %v, want %v", name, got, want)
		}
	}

	if res := remove(alice, aliceID); res.Code != http.StatusForbidden {
		t.Errorf("without users.manage: %d %s", res.Code, res.Body)
	}
	// hr has users.manage but not the admin's grants, so can't weaken the admin's login.
	if res := remove(hr, adminID); res.Code != http.StatusForbidden {
		t.Errorf("a user above the caller: %d %s", res.Code, res.Body)
	}
	if res := remove(admin, adminID); res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
		t.Errorf("one's own: %d %s", res.Code, res.Body)
	}
	if res := remove(admin, 999); res.Code != http.StatusNotFound {
		t.Errorf("a user who doesn't exist: %d %s", res.Code, res.Body)
	}
	for _, c := range []*client{admin, alice} {
		if st := totpStatus(t, c); !st.Enabled {
			t.Fatalf("a refused removal turned it off: %+v", st)
		}
	}

	before := len(e.auditRows())
	res := remove(admin, hrID) // hr doesn't have it
	mustStatus(t, res, http.StatusOK)
	if len(e.auditRows()) != before {
		t.Error("removing nothing was audited")
	}
	mustStatus(t, hr.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// A secret waiting for its first code isn't two-factor login yet, so there is nothing to remove.
	setupTOTP(t, hr, clock)
	mustStatus(t, remove(admin, hrID), http.StatusOK)
	if st := totpStatus(t, hr); !st.Pending || len(e.auditRows()) != before {
		t.Errorf("a pending secret was removed, or audited: %+v", st)
	}

	res = remove(admin, aliceID)
	mustStatus(t, res, http.StatusOK)
	if u := decode[gen.User](t, res); u.TotpEnabled || u.Username != "alice" {
		t.Errorf("the answer: %+v", u)
	}
	mustStatus(t, alice.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)
	alice = e.loggedIn("alice", "alice-password-1")
	if st := totpStatus(t, alice); st.Enabled || st.RecoveryCodesLeft != 0 {
		t.Errorf("alice after removal: %+v", st)
	}
	rows := e.auditRows()
	var removal *db.AuditLog
	for i := range rows {
		if rows[i].Action == "totp_disable" {
			removal = &rows[i]
		}
	}
	if removal == nil || removal.Username != "admin" || removal.Target != "user:alice" ||
		!strings.Contains(removal.Detail, `"by":"admin"`) || !strings.Contains(removal.Detail, `"sessions_ended":1`) {
		t.Errorf("audit row: %+v", removal)
	}
	if got, err := e.st.Read().CountUnusedRecoveryCodes(context.Background(), aliceID); err != nil || got != 0 {
		t.Errorf("alice's recovery codes after removal: %d, %v", got, err)
	}
}
