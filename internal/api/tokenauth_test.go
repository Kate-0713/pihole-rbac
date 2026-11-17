// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/tokens"
)

// tokenEnv is a targetEnv with a clock the test moves, shared by the server and the role manager.
type tokenEnv struct {
	*targetEnv
	now time.Time
}

func newTokenEnv(t *testing.T, modify ...func(*Options)) *tokenEnv {
	t.Helper()
	tk := &tokenEnv{now: time.Now().UTC().Truncate(time.Second)}
	clock := func(o *Options) {
		o.Now = func() time.Time { return tk.now }
		o.Roles.Now = o.Now
	}
	tk.targetEnv = newTargetEnv(t, append([]func(*Options){clock}, modify...)...)
	return tk
}

// makeToken creates a token for a user, with the grants given, expiring in 30 days, and returns it whole.
func (tk *tokenEnv) makeToken(username, name string, grants ...rbac.Grant) (secret, publicID string) {
	tk.t.Helper()
	ctx := context.Background()
	q := tk.st.Read()
	u, err := q.GetUserByUsername(ctx, username)
	if err != nil {
		tk.t.Fatal(err)
	}
	roles, err := q.ListUserRoleIDs(ctx, u.ID)
	if err != nil {
		tk.t.Fatal(err)
	}
	a := rbac.Actor{UserID: u.ID, Username: u.Username, Source: auth.MethodLocal, RoleIDs: roles, IP: "10.0.0.9"}
	nt, err := tk.srv.Roles.CreateToken(ctx, a, rbac.TokenInput{Name: name, ExpiresAt: tk.now.Add(30 * 24 * time.Hour), Grants: grants})
	if err != nil {
		tk.t.Fatalf("CreateToken: %v", err)
	}
	return nt.Secret, nt.Token.PublicID
}

// bearer sends a request with an API token in an Authorization header, as a script would: no cookies, no Origin and
// no CSRF token. header is the whole header value; "" sends no header at all.
func (tk *tokenEnv) bearer(header, method, path string, body any) response {
	tk.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			tk.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.RemoteAddr = "10.0.0.50:1234"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	w := httptest.NewRecorder()
	tk.h.ServeHTTP(w, r)
	return response{w}
}

func (tk *tokenEnv) userID(name string) int64 {
	tk.t.Helper()
	u, err := tk.st.Read().GetUserByUsername(context.Background(), name)
	if err != nil {
		tk.t.Fatal(err)
	}
	return u.ID
}

func (tk *tokenEnv) tx(fn func(q *db.Queries) error) {
	tk.t.Helper()
	if err := tk.st.WithTx(context.Background(), fn); err != nil {
		tk.t.Fatal(err)
	}
}

func wantError(t *testing.T, res response, status int, code string) {
	t.Helper()
	if res.Code != status || res.errorCode() != code {
		t.Fatalf("got %d %s, want %d %s", res.Code, res.Body, status, code)
	}
}

func TestTokenUse(t *testing.T) {
	tk := newTokenEnv(t)
	inst := rbac.InstanceScope(tk.id)
	secret, publicID := tk.makeToken("admin", "home assistant",
		rbac.Grant{Permission: rbac.BlockingToggle, Scope: inst}, rbac.Grant{Permission: rbac.DomainsView, Scope: inst})
	auth := "Bearer " + secret

	// A read the token's grants allow, and one they don't although the owner could.
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)
	mustStatus(t, tk.bearer(auth, http.MethodGet, "/api/v1/targets", nil), http.StatusOK)
	wantError(t, tk.bearer(auth, http.MethodGet, tk.path("/queries"), nil), http.StatusForbidden, "forbidden")

	// A write needs neither a CSRF token nor an Origin, and its audit row names the token.
	timer := 600
	res := tk.bearer(auth, http.MethodPut, tk.path("/blocking"), gen.BlockingInput{Enabled: false, Timer: &timer})
	if st := okResult[gen.BlockingWriteResult](tk.targetEnv, res).Blocking; st == nil || st.Blocking != "disabled" {
		t.Fatalf("disabling with a token: %s", res.Body)
	}
	row, detail := tk.lastAudit()
	if row.Action != audit.ActionBlockingSet || row.Username != "admin" || detail["via_token"] != "home assistant" ||
		detail["token_id"] != publicID {
		t.Errorf("audit %+v %v", row, detail)
	}

	// A write the token can't do is refused and audited as permission_denied, naming the token too.
	res = tk.bearer(auth, http.MethodPost, tk.path("/dns/restart"), nil)
	wantError(t, res, http.StatusForbidden, "forbidden")
	row, detail = tk.lastAudit()
	if row.Action != audit.ActionPermissionDenied || detail["via_token"] != "home assistant" {
		t.Errorf("refusal audit %+v %v", row, detail)
	}

	// The scheme is case-insensitive.
	mustStatus(t, tk.bearer("bearer "+secret, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
}

func TestTokenIgnoresCookies(t *testing.T) {
	tk := newTokenEnv(t)
	// The admin's browser session, with a bad token: no fall back to the session.
	r := tk.admin.request(http.MethodGet, tk.path("/blocking"), nil)
	r.Header.Set("Authorization", "Bearer nonsense")
	wantError(t, tk.admin.send(r), http.StatusUnauthorized, "invalid_token")
	// An empty header counts as a token too.
	r = tk.admin.request(http.MethodGet, tk.path("/blocking"), nil)
	r.Header["Authorization"] = []string{""}
	wantError(t, tk.admin.send(r), http.StatusUnauthorized, "invalid_token")
	// And a good token with someone else's session cookie is the token's owner.
	tk.addGrantUser("vic", "vic-password-1", grant(rbac.TokensUse, "all", 0), grant(rbac.DomainsView, "all", 0))
	secret, _ := tk.makeToken("vic", "reader", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	r = tk.admin.request(http.MethodPut, tk.path("/blocking"), gen.BlockingInput{Enabled: true})
	r.Header.Set("Authorization", "Bearer "+secret)
	wantError(t, tk.admin.send(r), http.StatusForbidden, "forbidden")
}

func TestTokenInvalid(t *testing.T) {
	tk := newTokenEnv(t, withLimits) // 4 failures per address
	secret, publicID := tk.makeToken("admin", "cron", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	wrong := secret[:len(secret)-1] + map[bool]string{true: "b", false: "a"}[strings.HasSuffix(secret, "a")]
	other, _, _ := tokens.New()

	for name, header := range map[string]string{
		"basic":          "Basic YWRtaW46cGFzc3dvcmQ=",
		"no scheme":      secret,
		"malformed":      "Bearer prt_short",
		"unknown":        "Bearer " + other,
		"wrong secret":   "Bearer " + wrong,
		"scheme alone":   "Bearer",
		"a second token": "Bearer " + secret + " " + secret,
	} {
		t.Run(name, func(t *testing.T) {
			tk.LoginByIPReset()
			res := tk.bearer(header, http.MethodGet, tk.path("/domains"), nil)
			wantError(t, res, http.StatusUnauthorized, "invalid_token")
			if !strings.Contains(res.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Errorf("WWW-Authenticate = %q", res.Header().Get("WWW-Authenticate"))
			}
		})
	}

	// Four failures from one address, then even the right token is turned away until the window passes.
	tk.LoginByIPReset()
	for range 4 {
		wantError(t, tk.bearer("Bearer "+wrong, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
	}
	res := tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil)
	wantError(t, res, http.StatusTooManyRequests, "rate_limited")
	if res.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}

	// Revoked, and a disabled owner: both just invalid.
	tk.LoginByIPReset()
	admin := tk.userID("admin")
	tk.tx(func(q *db.Queries) error {
		return q.SetUserDisabled(context.Background(), db.SetUserDisabledParams{Disabled: true, ID: admin})
	})
	wantError(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
	tk.tx(func(q *db.Queries) error {
		return q.SetUserDisabled(context.Background(), db.SetUserDisabledParams{Disabled: false, ID: admin})
	})
	mustStatus(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)
	if err := tk.srv.Roles.RevokeToken(context.Background(), rbac.Actor{UserID: admin, Username: "admin", RoleIDs: []int64{adminRoleID}}, publicID, false); err != nil {
		t.Fatal(err)
	}
	wantError(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
}

// LoginByIPReset clears the per-address count for the address bearer sends from.
func (tk *tokenEnv) LoginByIPReset() { tk.srv.LoginByIP.Reset("10.0.0.50") }

func TestTokenExpired(t *testing.T) {
	tk := newTokenEnv(t, withLimits)
	secret, publicID := tk.makeToken("admin", "cron", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	tk.now = tk.now.Add(30*24*time.Hour + time.Second)

	before := tk.auditCount()
	for range 6 { // more than the limit: expired uses don't count against it
		wantError(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "token_expired")
	}
	rows := tk.auditRows()[before:]
	if len(rows) != 1 || rows[0].Action != audit.ActionTokenExpiredUse || rows[0].Username != "admin" ||
		!strings.Contains(rows[0].Detail, publicID) {
		t.Fatalf("audit rows %+v, want one token_expired_use", rows)
	}
	// Audited again an hour later.
	tk.now = tk.now.Add(time.Hour)
	wantError(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "token_expired")
	if n := tk.auditCount(); n != before+2 {
		t.Errorf("%d new audit rows, want 2", n-before)
	}
}

func TestTokenNotAllowed(t *testing.T) {
	tk := newTokenEnv(t)
	secret, _ := tk.makeToken("admin", "everything",
		rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()}, rbac.Grant{Permission: rbac.AuditView, Scope: rbac.AllScope()})
	auth := "Bearer " + secret
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/users"},
		{http.MethodGet, "/api/v1/auth/session"},
		{http.MethodPost, "/api/v1/auth/logout"},
		{http.MethodGet, "/api/v1/sessions"},
		{http.MethodGet, "/api/v1/instances"},
		{http.MethodGet, "/api/v1/system/version"},
		{http.MethodGet, "/api/v1/about"},
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodGet, "/api/v1/roles"},
	} {
		wantError(t, tk.bearer(auth, c.method, c.path, nil), http.StatusForbidden, "token_not_allowed")
	}
	// The audit log can be read with audit.view.
	mustStatus(t, tk.bearer(auth, http.MethodGet, "/api/v1/audit", nil), http.StatusOK)
	mustStatus(t, tk.bearer(auth, http.MethodGet, "/api/v1/audit/export", nil), http.StatusOK)
}

func TestTokenFollowsOwner(t *testing.T) {
	tk := newTokenEnv(t)
	tk.addGrantUser("vic", "vic-password-1", grant(rbac.TokensUse, "all", 0), grant(rbac.DomainsView, "all", 0),
		grant(rbac.BlockingToggle, "all", 0))
	secret, _ := tk.makeToken("vic", "cron",
		rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()}, rbac.Grant{Permission: rbac.BlockingToggle, Scope: rbac.AllScope()})
	auth := "Bearer " + secret
	vic := tk.userID("vic")
	ctx := context.Background()
	role, err := tk.st.Read().ListUserRoleIDs(ctx, vic)
	if err != nil || len(role) != 1 {
		t.Fatal(role, err)
	}
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)
	setGrants := func(ps ...rbac.Permission) {
		t.Helper()
		tk.tx(func(q *db.Queries) error {
			if err := q.DeleteRoleGrants(ctx, role[0]); err != nil {
				return err
			}
			for _, p := range ps {
				if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: role[0], Permission: string(p)}); err != nil {
					return err
				}
			}
			return nil
		})
	}

	// Narrowing the owner's role narrows the token at once.
	setGrants(rbac.TokensUse, rbac.BlockingToggle)
	wantError(t, tk.bearer(auth, http.MethodGet, tk.path("/domains"), nil), http.StatusForbidden, "forbidden")
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)

	// Without tokens.use the token stops; a write is audited as refused.
	setGrants(rbac.BlockingToggle)
	res := tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil)
	wantError(t, res, http.StatusForbidden, "forbidden")
	if d := errorDetails(t, res); d["permission"] != string(rbac.TokensUse) {
		t.Errorf("details %v", d)
	}
	before := tk.auditCount()
	wantError(t, tk.bearer(auth, http.MethodPut, tk.path("/blocking"), gen.BlockingInput{Enabled: true}), http.StatusForbidden, "forbidden")
	if row, detail := tk.lastAudit(); tk.auditCount() != before+1 || row.Action != audit.ActionPermissionDenied || detail["via_token"] != "cron" {
		t.Errorf("refusal audit %+v %v", row, detail)
	}

	// Given back, the token works again.
	setGrants(rbac.TokensUse, rbac.BlockingToggle)
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)

	// An owner who must set up two-factor login is held, as their sessions are.
	tk.tx(func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: vic, Policy: "required", SetAt: 1, SetBy: "admin"})
	})
	wantError(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusForbidden, "totp_setup_required")
	tk.tx(func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: vic, Policy: "exempt", SetAt: 1, SetBy: "admin"})
	})
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
}

func TestTokenLastUse(t *testing.T) {
	tk := newTokenEnv(t)
	secret, _ := tk.makeToken("admin", "cron", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	lastUse := func() (time.Time, string) {
		t.Helper()
		ts, err := rbac.ListUserTokens(context.Background(), tk.st.Read(), tk.userID("admin"), tk.now)
		if err != nil || len(ts) != 1 {
			t.Fatal(ts, err)
		}
		return ts[0].LastUsedAt, ts[0].LastUsedIP
	}
	if at, _ := lastUse(); !at.IsZero() {
		t.Fatalf("a new token was used at %v", at)
	}
	first := tk.now
	mustStatus(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	if at, ip := lastUse(); !at.Equal(first) || ip != "10.0.0.50" {
		t.Errorf("after first use: %v from %q", at, ip)
	}
	tk.now = tk.now.Add(30 * time.Second)
	mustStatus(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	if at, _ := lastUse(); !at.Equal(first) {
		t.Errorf("written again within the minute: %v", at)
	}
	tk.now = tk.now.Add(31 * time.Second)
	mustStatus(t, tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	if at, _ := lastUse(); !at.Equal(tk.now) {
		t.Errorf("not written after a minute: %v, want %v", at, tk.now)
	}
}

func TestTokenClock(t *testing.T) {
	var c tokenClock
	t0 := time.Unix(1000, 0)
	if !c.due(1, t0, time.Minute) || c.due(1, t0.Add(59*time.Second), time.Minute) || !c.due(2, t0, time.Minute) {
		t.Fatal("first use, or another token, not due; or a second use within the interval due")
	}
	if !c.due(1, t0.Add(time.Minute), time.Minute) {
		t.Fatal("not due after the interval")
	}
	// Entries whose interval has passed are dropped as others are added.
	c.due(3, t0.Add(3*time.Minute), time.Minute)
	if len(c.last) != 1 {
		t.Errorf("%d entries kept, want 1", len(c.last))
	}
}
