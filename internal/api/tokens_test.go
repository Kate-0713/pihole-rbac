// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
	"github.com/Kate-0713/pihole-rbac/internal/tokens"
)

const accountTokens = "/api/v1/account/tokens"

func instanceGrant(p rbac.Permission, id int64) gen.Grant {
	return gen.Grant{Permission: string(p), Scope: gen.GrantScopeInstance, Id: &id}
}

func allGrant(p rbac.Permission) gen.Grant {
	return gen.Grant{Permission: string(p), Scope: gen.GrantScopeAll}
}

// tokenInput is a request for a token named name, expiring in 30 days, with the admin's password.
func (tk *tokenEnv) tokenInput(name string, grants ...gen.Grant) gen.APITokenInput {
	return gen.APITokenInput{Name: name, ExpiresAt: tk.now.Add(30 * 24 * time.Hour), Grants: grants, Password: "admin-password-1"}
}

func withCode(in gen.APITokenInput, code string) gen.APITokenInput {
	in.Code = &code
	return in
}

func TestCreateTokenEndpoint(t *testing.T) {
	tk := newTokenEnv(t)
	res := tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("  home assistant ",
		instanceGrant(rbac.BlockingToggle, tk.id), allGrant(rbac.AuditView)))
	mustStatus(t, res, http.StatusCreated)
	nt := decode[gen.NewAPIToken](t, res)
	publicID, _, ok := tokens.Parse(nt.Token)
	if !ok || publicID != nt.ApiToken.PublicId || nt.ApiToken.Name != "home assistant" || nt.ApiToken.Username != "admin" ||
		nt.ApiToken.State != gen.APITokenStateActive || len(nt.ApiToken.Grants) != 2 || nt.ApiToken.LastUsedAt != nil {
		t.Fatalf("new token %s", res.Body)
	}

	// It works straight away, within its grants.
	mustStatus(t, tk.bearer("Bearer "+nt.Token, http.MethodGet, tk.path("/blocking"), nil), http.StatusOK)
	mustStatus(t, tk.bearer("Bearer "+nt.Token, http.MethodGet, "/api/v1/audit", nil), http.StatusOK)

	// Listed, never with its secret.
	res = tk.admin.do(http.MethodGet, accountTokens, nil)
	mustStatus(t, res, http.StatusOK)
	list := decode[gen.APITokenList](t, res).Tokens
	secret := nt.Token[len(tokens.Prefix)+tokens.PublicIDLen+1:]
	if len(list) != 1 || list[0].PublicId != publicID || list[0].LastUsedAt == nil || list[0].LastUsedIp != "10.0.0.50" ||
		strings.Contains(res.Body.String(), secret) {
		t.Errorf("list %s", res.Body)
	}

	var row db.AuditLog
	for _, r := range tk.auditRows() {
		if r.Action == audit.ActionTokenCreate {
			row = r
		}
	}
	if row.Action != audit.ActionTokenCreate || row.Result != audit.ResultSuccess || strings.Contains(row.Detail, secret) {
		t.Errorf("audit %+v", row)
	}
	if strings.Contains(tk.audit.String(), secret) {
		t.Error("the AUDIT lines contain the secret")
	}
}

func TestCreateTokenRefusalsEndpoint(t *testing.T) {
	tk := newTokenEnv(t)
	ok := instanceGrant(rbac.DomainsView, tk.id)
	for name, c := range map[string]struct {
		in     gen.APITokenInput
		status int
		code   string
	}{
		"no password":             {gen.APITokenInput{Name: "x", ExpiresAt: tk.now.Add(time.Hour), Grants: []gen.Grant{ok}}, http.StatusBadRequest, "validation_failed"},
		"no grants":               {tk.tokenInput("x"), http.StatusBadRequest, "validation_failed"},
		"a grant with no id":      {tk.tokenInput("x", gen.Grant{Permission: string(rbac.DomainsView), Scope: gen.GrantScopeInstance}), http.StatusBadRequest, "validation_failed"},
		"a management permission": {tk.tokenInput("x", allGrant(rbac.UsersManage)), http.StatusBadRequest, "validation_failed"},
		"over a year":             {gen.APITokenInput{Name: "x", ExpiresAt: tk.now.Add(366 * 24 * time.Hour), Grants: []gen.Grant{ok}, Password: "admin-password-1"}, http.StatusBadRequest, "validation_failed"},
		"a past expiry":           {gen.APITokenInput{Name: "x", ExpiresAt: tk.now.Add(-time.Hour), Grants: []gen.Grant{ok}, Password: "admin-password-1"}, http.StatusBadRequest, "validation_failed"},
		"a blank name":            {tk.tokenInput("   ", ok), http.StatusBadRequest, "validation_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			wantError(t, tk.admin.do(http.MethodPost, accountTokens, c.in), c.status, c.code)
		})
	}
	mustStatus(t, tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("cron", ok)), http.StatusCreated)
	res := tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("cron", ok))
	wantError(t, res, http.StatusConflict, "conflict")
	if errorDetails(t, res)["reason"] != "name_taken" {
		t.Errorf("details %s", res.Body)
	}

	// Without tokens.use the gate refuses before the password is looked at.
	tk.addGrantUser("pat", "pat-password-1", grant(rbac.DomainsView, "all", 0))
	pat := tk.loggedIn("pat", "pat-password-1")
	calls := tk.authn.calls
	in := tk.tokenInput("x", ok)
	in.Password = "pat-password-1"
	res = pat.do(http.MethodPost, accountTokens, in)
	wantError(t, res, http.StatusForbidden, "forbidden")
	if tk.authn.calls != calls {
		t.Error("the password was checked for a caller without tokens.use")
	}
	// With it, only what they hold.
	tk.addGrantUser("vic", "vic-password-1", grant(rbac.TokensUse, "all", 0), grant(rbac.DomainsView, "instance", tk.id))
	vic := tk.loggedIn("vic", "vic-password-1")
	in = tk.tokenInput("x", allGrant(rbac.DomainsView))
	in.Password = "vic-password-1"
	res = vic.do(http.MethodPost, accountTokens, in)
	wantError(t, res, http.StatusForbidden, "forbidden")
	if d := errorDetails(t, res); d["missing"] == nil {
		t.Errorf("details %v", d)
	}
	in.Grants = []gen.Grant{ok}
	mustStatus(t, vic.do(http.MethodPost, accountTokens, in), http.StatusCreated)

	// Neither a token nor a missing CSRF token can make one.
	nt := decode[gen.NewAPIToken](t, tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("maker", ok)))
	wantError(t, tk.bearer("Bearer "+nt.Token, http.MethodPost, accountTokens, tk.tokenInput("more", ok)), http.StatusForbidden, "token_not_allowed")
	r := tk.admin.request(http.MethodPost, accountTokens, tk.tokenInput("no csrf", ok))
	r.Header.Del("X-CSRF-Token")
	wantError(t, tk.admin.send(r), http.StatusForbidden, "csrf_failed")
}

func TestCreateTokenWrongPassword(t *testing.T) {
	tk := newTokenEnv(t, withLimits) // 3 failures per username
	ok := instanceGrant(rbac.DomainsView, tk.id)
	in := tk.tokenInput("x", ok)
	in.Password = "not-the-password"
	for range 3 {
		wantError(t, tk.admin.do(http.MethodPost, accountTokens, in), http.StatusUnauthorized, "invalid_credentials")
	}
	if n := auditCount(tk.testEnv, audit.ActionTokenCreate, audit.ResultFailure); n != 3 {
		t.Errorf("%d failed token_create rows, want 3", n)
	}
	// The limit now applies, even with the right password.
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("x", ok)), http.StatusTooManyRequests, "rate_limited")
	res := tk.admin.do(http.MethodGet, accountTokens, nil)
	if list := decode[gen.APITokenList](t, res).Tokens; len(list) != 0 {
		t.Errorf("tokens made: %s", res.Body)
	}
}

func TestCreateTokenWithTOTP(t *testing.T) {
	clock := &totpClock{at: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	tk := newTokenEnv(t, withTOTP(clock))
	app, recovery := enableTOTP(t, tk.admin, clock)
	ok := instanceGrant(rbac.DomainsView, tk.id)

	// A code is required, and a wrong one refused and audited.
	res := tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("x", ok))
	wantError(t, res, http.StatusBadRequest, "validation_failed")
	if errorDetails(t, res)["field"] != "code" {
		t.Errorf("details %s", res.Body)
	}
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("x", ok), wrongCode(app.code()))),
		http.StatusUnauthorized, "totp_invalid")
	if n := auditCount(tk.testEnv, audit.ActionTokenCreate, audit.ResultFailure); n != 1 {
		t.Errorf("%d failed token_create rows, want 1", n)
	}

	// A code isn't spent when the token can't be made: refused for its name, then the same code makes one.
	mustStatus(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("taken", ok), app.code())), http.StatusCreated)
	clock.nextStep()
	code := app.code()
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("taken", ok), code)), http.StatusConflict, "conflict")
	mustStatus(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("second", ok), code)), http.StatusCreated)
	// That code is spent now.
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("third", ok), code)), http.StatusUnauthorized, "totp_invalid")

	// A recovery code works once, and its use is audited.
	mustStatus(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("by recovery", ok), recovery[0])), http.StatusCreated)
	if n := auditCount(tk.testEnv, audit.ActionRecoveryCodeUsed, audit.ResultSuccess); n != 1 {
		t.Errorf("%d recovery_code_used rows, want 1", n)
	}
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("again", ok), recovery[0])), http.StatusUnauthorized, "totp_invalid")

	// A wrong password isn't helped by a right code, and doesn't spend it.
	clock.nextStep()
	in := withCode(tk.tokenInput("x", ok), app.code())
	in.Password = "wrong"
	wantError(t, tk.admin.do(http.MethodPost, accountTokens, in), http.StatusUnauthorized, "invalid_credentials")
	mustStatus(t, tk.admin.do(http.MethodPost, accountTokens, withCode(tk.tokenInput("after", ok), app.code())), http.StatusCreated)
}

func TestRevokeTokenEndpoints(t *testing.T) {
	tk := newTokenEnv(t)
	ok := instanceGrant(rbac.DomainsView, tk.id)
	mine := decode[gen.NewAPIToken](t, tk.admin.do(http.MethodPost, accountTokens, tk.tokenInput("mine", ok)))

	tk.addGrantUser("vic", "vic-password-1", grant(rbac.TokensUse, "all", 0), grant(rbac.DomainsView, "all", 0))
	vic := tk.loggedIn("vic", "vic-password-1")
	in := tk.tokenInput("vics", ok)
	in.Password = "vic-password-1"
	theirs := decode[gen.NewAPIToken](t, vic.do(http.MethodPost, accountTokens, in))

	// Vic can't see or revoke the admin's, and can't use the admin list.
	if list := decode[gen.APITokenList](t, vic.do(http.MethodGet, accountTokens, nil)).Tokens; len(list) != 1 || list[0].Name != "vics" {
		t.Errorf("vic's list %+v", list)
	}
	wantError(t, vic.do(http.MethodDelete, accountTokens+"/"+mine.ApiToken.PublicId, nil), http.StatusNotFound, "not_found")
	wantError(t, vic.do(http.MethodGet, "/api/v1/tokens", nil), http.StatusForbidden, "forbidden")
	wantError(t, vic.do(http.MethodDelete, "/api/v1/tokens/"+mine.ApiToken.PublicId, nil), http.StatusForbidden, "forbidden")
	// Nor can the admin revoke vic's from their own account page.
	wantError(t, tk.admin.do(http.MethodDelete, accountTokens+"/"+theirs.ApiToken.PublicId, nil), http.StatusNotFound, "not_found")

	// The admin list has both, by owner.
	res := tk.admin.do(http.MethodGet, "/api/v1/tokens", nil)
	mustStatus(t, res, http.StatusOK)
	all := decode[gen.APITokenList](t, res).Tokens
	if len(all) != 2 || all[0].Username != "admin" || all[1].Username != "vic" {
		t.Errorf("all tokens %s", res.Body)
	}

	// Revoking stops a token at once; again is fine.
	mustStatus(t, vic.do(http.MethodDelete, accountTokens+"/"+theirs.ApiToken.PublicId, nil), http.StatusNoContent)
	wantError(t, tk.bearer("Bearer "+theirs.Token, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
	mustStatus(t, vic.do(http.MethodDelete, accountTokens+"/"+theirs.ApiToken.PublicId, nil), http.StatusNoContent)

	mustStatus(t, tk.bearer("Bearer "+mine.Token, http.MethodGet, tk.path("/domains"), nil), http.StatusOK)
	mustStatus(t, tk.admin.do(http.MethodDelete, "/api/v1/tokens/"+mine.ApiToken.PublicId, nil), http.StatusNoContent)
	wantError(t, tk.bearer("Bearer "+mine.Token, http.MethodGet, tk.path("/domains"), nil), http.StatusUnauthorized, "invalid_token")
	if list := decode[gen.APITokenList](t, tk.admin.do(http.MethodGet, accountTokens, nil)).Tokens; list[0].State != gen.APITokenStateRevoked || list[0].RevokedAt == nil {
		t.Errorf("after revoking: %+v", list[0])
	}
	if n := auditCount(tk.testEnv, audit.ActionTokenRevoke, audit.ResultSuccess); n != 2 {
		t.Errorf("%d token_revoke rows, want 2", n)
	}
	// A malformed ID is simply not found.
	wantError(t, tk.admin.do(http.MethodDelete, accountTokens+"/NOT-AN-ID", nil), http.StatusNotFound, "not_found")
}

func TestTokenGrantableEndpoint(t *testing.T) {
	e := newTestEnv(t)
	e.topology() // instances A, B, C (1-3); mirrored group 1 of A and B; independent group 2 of B and C
	e.addGrantUser("vic", "vic-password-1",
		grant(rbac.TokensUse, "all", 0),
		grant(rbac.DomainsView, "instance", 1),
		grant(rbac.DriftView, "group", 1),
		grant(rbac.UsersManage, "all", 0),
	)
	vic := e.loggedIn("vic", "vic-password-1")
	res := vic.do(http.MethodGet, accountTokens+"/grantable", nil)
	mustStatus(t, res, http.StatusOK)
	g := decode[gen.TokenGrantable](t, res)
	if len(g.Permissions) != 2 || g.Permissions[0].Name != "domains.view" || g.Permissions[0].All ||
		len(g.Permissions[0].Instances) != 1 || g.Permissions[0].Instances[0] != 1 || len(g.Permissions[0].Groups) != 0 ||
		g.Permissions[1].Name != "drift.view" || len(g.Permissions[1].Groups) != 1 || g.Permissions[1].Description == "" {
		t.Errorf("permissions %s", res.Body)
	}
	// Only the names of what it offers: instance A and the mirrored group, not B, C or the independent group.
	if len(g.Instances) != 1 || g.Instances[0].Name != "A" || len(g.Groups) != 1 || g.Groups[0].Name != "mirror" {
		t.Errorf("names %s", res.Body)
	}

	// Without tokens.use it is refused.
	e.addGrantUser("pat", "pat-password-1", grant(rbac.DomainsView, "all", 0))
	wantError(t, e.loggedIn("pat", "pat-password-1").do(http.MethodGet, accountTokens+"/grantable", nil), http.StatusForbidden, "forbidden")
}
