// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"github.com/Kate-0713/pihole-rbac/internal/metrics/metricstest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func withRegistry(o *Options) { o.MetricsRegistry = metrics.New() }

func scrapeText(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func wantSeries(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestHTTPMetrics(t *testing.T) {
	te := newTargetEnv(t, withRegistry)
	mustStatus(t, te.admin.do(http.MethodGet, te.path("/blocking"), nil), http.StatusOK)
	mustStatus(t, te.admin.do(http.MethodGet, "/api/v1/nonexistent", nil), http.StatusNotFound)
	mustStatus(t, te.admin.do(http.MethodGet, "/api/v1/targets", nil), http.StatusOK)
	// Paths a scanner invents must not become series.
	for _, p := range []string{"/api/v1/targets/i-1/zzz", "/api/aaa", "/api/bbb"} {
		te.admin.do(http.MethodGet, p, nil)
	}

	out := scrapeText(t, te.srv.MetricsRegistry)
	wantSeries(t, out,
		`pihole_rbac_http_requests_total{route="GET /api/v1/targets/{target}/blocking",code_class="2xx"} 1`,
		`pihole_rbac_http_requests_total{route="GET /api/v1/targets",code_class="2xx"} 1`,
		`pihole_rbac_http_requests_total{route="/api/",code_class="4xx"} `,
		`pihole_rbac_http_request_duration_seconds_count{route="GET /api/v1/targets"} 1`,
	)
	if strings.Contains(out, "nonexistent") || strings.Contains(out, "aaa") || strings.Contains(out, "zzz") {
		t.Errorf("a request path became a label:\n%s", out)
	}
	metricstest.Dump(t, te.srv.MetricsRegistry)
}

func TestStatusWriter(t *testing.T) {
	// Flush and Unwrap reach the real writer, so streaming and http.ResponseController keep working.
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	sw.WriteHeader(http.StatusTeapot)
	sw.WriteHeader(http.StatusOK) // ignored: the first status stands
	sw.Flush()
	if sw.status != http.StatusTeapot || !rec.Flushed || sw.Unwrap() != rec {
		t.Errorf("status %d, flushed %v", sw.status, rec.Flushed)
	}
	// A 1xx isn't the final status.
	sw = &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw.WriteHeader(http.StatusEarlyHints)
	sw.WriteHeader(http.StatusNoContent)
	if sw.status != http.StatusNoContent {
		t.Errorf("status %d, want 204", sw.status)
	}
	for status, want := range map[int]string{200: "2xx", 207: "2xx", 302: "3xx", 429: "4xx", 502: "5xx", 0: "other", 700: "other"} {
		if got := codeClass(status); got != want {
			t.Errorf("codeClass(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestWriteMetrics(t *testing.T) {
	ge := newGroupEnv(t, withRegistry)
	mustStatus(t, ge.admin.do(http.MethodPut, ge.path("/blocking"), gen.BlockingInput{Enabled: true}), http.StatusOK)
	// Reads aren't writes.
	mustStatus(t, ge.admin.do(http.MethodGet, ge.path("/blocking"), nil), http.StatusOK)

	ge.down("gamma")
	if res := ge.admin.do(http.MethodPost, ge.path("/dns/restart"), nil); res.Code != http.StatusMultiStatus {
		t.Fatalf("restart: %d %s", res.Code, res.Body)
	}
	ge.down("alpha")
	ge.down("beta")
	if res := ge.admin.do(http.MethodPut, ge.path("/blocking"), gen.BlockingInput{Enabled: true}); res.Code != http.StatusBadGateway {
		t.Fatalf("blocking: %d %s", res.Code, res.Body)
	}
	wantSeries(t, scrapeText(t, ge.srv.MetricsRegistry),
		`pihole_rbac_writes_total{result="ok"} 1`,
		`pihole_rbac_writes_total{result="partial"} 1`,
		`pihole_rbac_writes_total{result="failed"} 1`,
	)
	metricstest.Dump(t, ge.srv.MetricsRegistry)
}

func TestTokenMetrics(t *testing.T) {
	tk := newTokenEnv(t, withLimits, withRegistry) // 4 failures per address
	secret, publicID := tk.makeToken("admin", "cron", rbac.Grant{Permission: rbac.DomainsView, Scope: rbac.AllScope()})
	good := "Bearer " + secret
	path := tk.path("/domains")

	mustStatus(t, tk.bearer(good, http.MethodGet, path, nil), http.StatusOK)
	wantError(t, tk.bearer("Bearer prt_short", http.MethodGet, path, nil), http.StatusUnauthorized, "invalid_token")
	wantError(t, tk.bearer(good, http.MethodGet, "/api/v1/users", nil), http.StatusForbidden, "token_not_allowed")

	// Expired, then rate limited.
	tk.now = tk.now.Add(30*24*time.Hour + time.Second)
	wantError(t, tk.bearer(good, http.MethodGet, path, nil), http.StatusUnauthorized, "token_expired")
	tk.now = tk.now.Add(-30*24*time.Hour - time.Second)
	for range 3 {
		tk.bearer("Bearer prt_short", http.MethodGet, path, nil)
	}
	wantError(t, tk.bearer(good, http.MethodGet, path, nil), http.StatusTooManyRequests, "rate_limited")

	// Revoked.
	tk.LoginByIPReset()
	admin := tk.userID("admin")
	if err := tk.srv.Roles.RevokeToken(t.Context(), rbac.Actor{UserID: admin, Username: "admin", RoleIDs: []int64{adminRoleID}}, publicID, false); err != nil {
		t.Fatal(err)
	}
	wantError(t, tk.bearer(good, http.MethodGet, path, nil), http.StatusUnauthorized, "invalid_token")

	out := scrapeText(t, tk.srv.MetricsRegistry)
	wantSeries(t, out,
		`pihole_rbac_api_token_requests_total{result="ok"} 1`,
		`pihole_rbac_api_token_requests_total{result="invalid"} 4`,
		`pihole_rbac_api_token_requests_total{result="not_allowed"} 1`,
		`pihole_rbac_api_token_requests_total{result="expired"} 1`,
		`pihole_rbac_api_token_requests_total{result="rate_limited"} 1`,
		`pihole_rbac_api_token_requests_total{result="revoked"} 1`,
	)
	if strings.Contains(out, secret) || strings.Contains(out, publicID) {
		t.Error("a token appears in the metrics")
	}
	metricstest.Dump(t, tk.srv.MetricsRegistry)
}

// Logins are counted from the rows the handlers write: the password step of a two-factor login isn't finished and
// counts nothing, a wrong code and a wrong password are failures, and the right code is the one success.
func TestLoginMetrics(t *testing.T) {
	e, clock := newTOTPEnv(t)
	_, app, _ := totpUser(t, e, clock, "alice", "alice-password-1")
	reg := metrics.New()
	e.srv.Audit.SetMetrics(reg)

	c := e.client("10.0.0.1:1")
	if res := c.login("alice", "alice-password-1"); res.Code != http.StatusAccepted {
		t.Fatalf("password step: %d %s", res.Code, res.Body)
	}
	if out := scrapeText(t, reg); strings.Contains(out, "logins_total{") {
		t.Errorf("the password step was counted:\n%s", out)
	}
	if res := c.loginTOTP(wrongCode(app.code())); res.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %s", res.Code, res.Body)
	}
	if res := c.loginTOTP(app.code()); res.Code != http.StatusOK {
		t.Fatalf("right code: %d %s", res.Code, res.Body)
	}
	if res := e.client("10.0.0.2:1").login("alice", "not the password"); res.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", res.Code)
	}

	out := scrapeText(t, reg)
	wantSeries(t, out,
		`pihole_rbac_logins_total{result="ok"} 1`,
		`pihole_rbac_logins_total{result="failed"} 2`,
		`pihole_rbac_audit_events_total{action="login",result="success"} 1`,
		`pihole_rbac_audit_events_total{action="login",result="failure"} 2`,
	)
	if strings.Contains(out, "alice") {
		t.Errorf("a username became a label:\n%s", out)
	}
	metricstest.Dump(t, reg)
}

// Nothing a client sends, and no secret, becomes part of the output: a hostile username, a wrong bearer token and a
// wrong metrics token are counted by kind only.
func TestMetricsOutputHoldsNoInput(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken), func(o *Options) { o.MetricsRegistry.Counter("keep_total", "x").Inc() })
	e.srv.Audit.SetMetrics(e.srv.MetricsRegistry)
	e.addUser("admin", "admin-password-1", true)

	hostile := "evil\"}\ninjected_metric 1 #"
	c := e.client("10.0.0.1:1")
	c.login(hostile, "hostile-password-xyz")
	c.login("admin", "admin-password-1")
	e.client("10.0.0.2:1").do(http.MethodGet, "/api/v1/zz-scanner-path", nil)
	r := c.request(http.MethodGet, "/api/v1/targets", nil)
	r.Header.Set("Authorization", "Bearer prt_not-a-real-token-value")
	c.send(r)

	res := c.scrape("Bearer " + testMetricsToken)
	if res.Code != http.StatusOK {
		t.Fatalf("scrape: %d %s", res.Code, res.Body)
	}
	out := res.Body.String()
	for _, secret := range []string{
		"injected_metric", "evil", "hostile-password-xyz", "admin-password-1", "prt_not-a-real-token-value",
		testMetricsToken, "zz-scanner-path", "10.0.0.1", "10.0.0.2",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("the output contains %q", secret)
		}
	}
}
