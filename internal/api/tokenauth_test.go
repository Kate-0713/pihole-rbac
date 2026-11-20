// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"database/sql"
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
	"github.com/Kate-0713/pihole-rbac/internal/store"
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
	secret, publicID := tk.makeToken("vic", "cron",
		rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()}, rbac.Grant{Permission: rbac.BlockingToggle, Scope: rbac.AllScope()})
	auth := "Bearer " + secret
	// The admin list says the same as the gate: why a live token is refused, while it stays active.
	listed := func(want string) {
		t.Helper()
		for _, lt := range decode[gen.APITokenList](t, tk.admin.do(http.MethodGet, "/api/v1/tokens", nil)).Tokens {
			if lt.PublicId != publicID {
				continue
			}
			got := ""
			if lt.Refused != nil {
				got = string(*lt.Refused)
			}
			if got != want || lt.State != gen.APITokenStateActive {
				t.Errorf("listed as %s, refused %q, want active, refused %q", lt.State, got, want)
			}
			return
		}
		t.Errorf("token %s not listed", publicID)
	}
	vic := tk.userID("vic")
	ctx := context.Background()
	role, err := tk.st.Read().ListUserRoleIDs(ctx, vic)
	if err != nil || len(role) != 1 {
		t.Fatal(role, err)
	}
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)
	listed("")
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
	listed("lacks_tokens_use")
	before := tk.auditCount()
	wantError(t, tk.bearer(auth, http.MethodPut, tk.path("/blocking"), gen.BlockingInput{Enabled: true}), http.StatusForbidden, "forbidden")
	if row, detail := tk.lastAudit(); tk.auditCount() != before+1 || row.Action != audit.ActionPermissionDenied || detail["via_token"] != "cron" {
		t.Errorf("refusal audit %+v %v", row, detail)
	}

	// Given back, the token works again.
	setGrants(rbac.TokensUse, rbac.BlockingToggle)
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	listed("")

	// An owner who must set up two-factor login is held, as their sessions are.
	tk.tx(func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: vic, Policy: "required", SetAt: 1, SetBy: "admin"})
	})
	wantError(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusForbidden, "totp_setup_required")
	listed("totp_setup_required")
	tk.tx(func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: vic, Policy: "exempt", SetAt: 1, SetBy: "admin"})
	})
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)

	// A disabled owner's token is refused as invalid, and listed as refused for that reason; enabled, it works again.
	setDisabled := func(d bool) {
		t.Helper()
		tk.tx(func(q *db.Queries) error {
			return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: d, ID: vic})
		})
	}
	setDisabled(true)
	wantError(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusUnauthorized, "invalid_token")
	listed("owner_disabled")
	setDisabled(false)
	mustStatus(t, tk.bearer(auth, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	listed("")
}

func TestTokenLastUse(t *testing.T) {
	tk := newTokenEnv(t)
	secret, _ := tk.makeToken("admin", "cron", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	lastUse := func() (time.Time, string) {
		t.Helper()
		ts, err := rbac.ListUserTokens(context.Background(), tk.st.Read(), tk.userID("admin"), tk.now, 0)
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

// An LDAP user's token uses the roles it holds, is suspended (not ended) once they are older than the recheck window,
// and works again when a recheck confirms them.
func TestLDAPToken(t *testing.T) {
	dir := &stubLDAP{users: map[string]stubLDAPUser{
		"dana": {password: "dana-password", dn: "CN=Dana,DC=example,DC=local", groups: []string{adminGroupDN}},
	}}
	now := time.Now().UTC()
	e := newLDAPEnv(t, dir, withLimits, func(o *Options) { o.Now = func() time.Time { return now } })
	e.addUser("admin", "admin-password-1", true)
	dana := e.loggedIn("dana", "dana-password")
	res := dana.do(http.MethodPost, accountTokens, gen.APITokenInput{
		Name: "siem", ExpiresAt: now.Add(24 * time.Hour), Grants: []gen.Grant{allGrant(rbac.AuditView)}, Password: "dana-password",
	})
	mustStatus(t, res, http.StatusCreated)
	nt := decode[gen.NewAPIToken](t, res)
	tokenRow, err := e.st.Read().GetAPITokenForAuth(t.Context(), nt.ApiToken.PublicId)
	if err != nil {
		t.Fatal(err)
	}
	tokenID := tokenRow.ID
	// The token starts from when its session's roles were last confirmed. The sessions use the real clock, not the
	// test's, so that moment is a little after the test's own start, and by more the slower the machine is.
	rolesChecked := store.FromMillis(tokenRow.RolesCheckedAt.Int64)
	get := func(path string) response {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "10.0.0.60:1"
		r.Header.Set("Authorization", "Bearer "+nt.Token)
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		return response{w}
	}
	listed := func() gen.APITokenState {
		t.Helper()
		return decode[gen.APITokenList](t, dana.do(http.MethodGet, accountTokens, nil)).Tokens[0].State
	}

	mustStatus(t, get("/api/v1/audit"), http.StatusOK)
	if s := listed(); s != gen.APITokenStateActive {
		t.Errorf("listed as %s", s)
	}

	// Past the recheck interval plus the grace period without a recheck: suspended, more often than the login limit
	// allows failures, since it isn't one.
	now = rolesChecked.Add(auth.DefaultRecheckInterval + auth.DefaultRecheckGrace + time.Second)
	for range 6 {
		wantError(t, get("/api/v1/audit"), http.StatusUnauthorized, "token_suspended")
	}
	if s := listed(); s != gen.APITokenStateSuspended {
		t.Errorf("listed as %s, want suspended", s)
	}
	// A suspended token's roles aren't trusted, so only a disabled owner is given as a reason, as the gate checks it
	// first.
	admin := e.loggedIn("admin", "admin-password-1")
	adminListed := func() gen.APIToken {
		t.Helper()
		return decode[gen.APITokenList](t, admin.do(http.MethodGet, "/api/v1/tokens", nil)).Tokens[0]
	}
	if lt := adminListed(); lt.Refused != nil {
		t.Errorf("suspended token refused %v", *lt.Refused)
	}
	setDisabled := func(d bool) {
		t.Helper()
		if err := e.st.WithTx(t.Context(), func(q *db.Queries) error {
			return q.SetUserDisabled(t.Context(), db.SetUserDisabledParams{Disabled: d, ID: nt.ApiToken.UserId})
		}); err != nil {
			t.Fatal(err)
		}
	}
	setDisabled(true)
	if lt := adminListed(); lt.State != gen.APITokenStateSuspended || lt.Refused == nil || *lt.Refused != gen.OwnerDisabled {
		t.Errorf("listed as %s, refused %v, want suspended and owner_disabled", lt.State, lt.Refused)
	}
	setDisabled(false)

	// A successful recheck resumes it.
	tx := func(fn func(q *db.Queries) error) {
		t.Helper()
		if err := e.st.WithTx(t.Context(), fn); err != nil {
			t.Fatal(err)
		}
	}
	tx(func(q *db.Queries) error {
		return q.SetUserTokensRolesChecked(t.Context(), db.SetUserTokensRolesCheckedParams{
			RolesCheckedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, UserID: nt.ApiToken.UserId,
		})
	})
	mustStatus(t, get("/api/v1/audit"), http.StatusOK)

	// Its permissions come from the roles it holds: with none left, tokens.use is gone too.
	tx(func(q *db.Queries) error { return q.ClearAPITokenRoles(t.Context(), tokenID) })
	res = get("/api/v1/audit")
	wantError(t, res, http.StatusForbidden, "forbidden")
	if d := errorDetails(t, res); d["permission"] != string(rbac.TokensUse) {
		t.Errorf("details %v", d)
	}
	// Her own list says so from the token's roles, though her session still holds tokens.use.
	if lt := decode[gen.APITokenList](t, dana.do(http.MethodGet, accountTokens, nil)).Tokens[0]; lt.State != gen.APITokenStateActive ||
		lt.Refused == nil || *lt.Refused != gen.LacksTokensUse {
		t.Errorf("listed as %s, refused %v", lt.State, lt.Refused)
	}
}

// A revoked token, or one whose owner is disabled, has the right secret: it is refused with the same answer as any
// invalid token, but isn't counted against the login limit, so a script left running with it can't lock out its
// address. A wrong secret still is counted.
func TestTokenRefusalsCountedOnlyForGuesses(t *testing.T) {
	tk := newTokenEnv(t, withLimits) // 4 failures per address
	ctx := context.Background()
	admin := tk.userID("admin")
	adminActor := rbac.Actor{UserID: admin, Username: "admin", RoleIDs: []int64{adminRoleID}}

	tk.addGrantUser("vic", "vic-password-1", grant(rbac.TokensUse, "all", 0), grant(rbac.DomainsView, "all", 0))
	disabledSecret, _ := tk.makeToken("vic", "owner disabled", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	revokedSecret, revokedID := tk.makeToken("admin", "revoked", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	goodSecret, _ := tk.makeToken("admin", "good", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	if err := tk.srv.Roles.RevokeToken(ctx, adminActor, revokedID, false); err != nil {
		t.Fatal(err)
	}
	vic := tk.userID("vic")
	tk.tx(func(q *db.Queries) error {
		return q.SetUserDisabled(ctx, db.SetUserDisabledParams{Disabled: true, ID: vic})
	})

	for name, secret := range map[string]string{"revoked": revokedSecret, "owner disabled": disabledSecret} {
		for i := range 6 {
			res := tk.bearer("Bearer "+secret, http.MethodGet, tk.path("/domains"), nil)
			if res.Code != http.StatusUnauthorized || res.errorCode() != "invalid_token" {
				t.Fatalf("%s, use %d: got %d %s, want 401 invalid_token", name, i+1, res.Code, res.Body)
			}
		}
	}
	// None of that counted: a good token still works.
	mustStatus(t, tk.bearer("Bearer "+goodSecret, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)

	// A wrong secret does count.
	wrong := goodSecret[:len(goodSecret)-1] + map[bool]string{true: "b", false: "a"}[strings.HasSuffix(goodSecret, "a")]
	for range 4 {
		wantError(t, tk.bearer("Bearer "+wrong, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
	}
	wantError(t, tk.bearer("Bearer "+goodSecret, http.MethodGet, tk.path("/domains"), nil), http.StatusTooManyRequests, "rate_limited")
}
