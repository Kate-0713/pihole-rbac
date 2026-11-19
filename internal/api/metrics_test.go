// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

const testMetricsToken = "scrape-token-0123456789-abcdefghijklmnop"

// withMetrics gives the server a metrics token from the environment ("" for none), a registry holding one counter,
// and a wrong-token limiter that trips at 3 failures.
func withMetrics(token string) func(*Options) {
	return func(o *Options) {
		sec, err := secrets.Load(secrets.Options{
			DataDir: os.TempDir(),
			Getenv: func(k string) string {
				if k == secrets.VarMetricsToken {
					return token
				}
				return ""
			},
			Environ: func() []string { return nil },
		})
		if err != nil {
			panic(err)
		}
		o.Secrets = sec
		o.MetricsRegistry = metrics.New()
		o.MetricsRegistry.Counter("test_scrapes_total", "A counter for the test.").Inc()
		o.MetricsByIP = ratelimit.New(3, 15*time.Minute)
	}
}

func (c *client) scrape(authorization ...string) response {
	r := c.request(http.MethodGet, "/metrics", nil)
	for _, a := range authorization {
		r.Header.Add("Authorization", a)
	}
	return c.send(r)
}

func TestMetricsIsOffWithoutAToken(t *testing.T) {
	e := newTestEnv(t, withMetrics(""))
	c := e.client("10.0.0.1:1")
	// Not 401, and not the SPA's index.html: nothing says there is anything here. Wrong headers count nothing, so
	// there is no 429 however many come.
	for i := 0; i < 20; i++ {
		for _, auth := range [][]string{nil, {"Bearer " + testMetricsToken}, {"Bearer wrong"}} {
			res := c.scrape(auth...)
			if res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
				t.Fatalf("status %d, code %q; want 404 not_found", res.Code, res.errorCode())
			}
			if strings.Contains(res.Body.String(), "<html") {
				t.Fatal("answered with the frontend")
			}
		}
	}
}

func TestMetricsWithoutASecretsManagerIsOff(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.Secrets = nil })
	if res := e.client("10.0.0.1:1").scrape("Bearer " + testMetricsToken); res.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", res.Code)
	}
}

func TestMetricsWithTheRightToken(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken))
	c := e.client("10.0.0.1:1")
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		res := c.scrape(scheme + " " + testMetricsToken)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", scheme, res.Code, res.Body)
		}
		if got := res.Header().Get("Content-Type"); got != metrics.ContentType {
			t.Errorf("Content-Type = %q, want %q", got, metrics.ContentType)
		}
		if got := res.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q", got)
		}
		if !strings.Contains(res.Body.String(), "test_scrapes_total 1\n") {
			t.Errorf("body doesn't hold the registry's counter:\n%s", res.Body)
		}
	}
	if res := c.do(http.MethodHead, "/metrics", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("HEAD without a token: %d, want 401", res.Code)
	}
}

func TestMetricsIsAnsweredBeforeSetupIsComplete(t *testing.T) {
	e := newSetupEnv(t, withMetrics(testMetricsToken))
	c := e.client("10.0.0.1:1")
	if res := c.scrape("Bearer " + testMetricsToken); res.Code != http.StatusOK {
		t.Fatalf("with the token: %d %s", res.Code, res.Body)
	}
	if res := c.scrape(); res.Code != http.StatusUnauthorized {
		t.Fatalf("without it: %d, want 401, not setup_required", res.Code)
	}
}

func TestMetricsRefusesAWrongToken(t *testing.T) {
	// A fresh server for each, so the limiter never gets in the way.
	tests := []struct {
		name string
		auth []string
	}{
		{"no header", nil},
		{"empty header", []string{""}},
		{"basic", []string{"Basic " + testMetricsToken}},
		{"no scheme", []string{testMetricsToken}},
		{"bearer without a token", []string{"Bearer"}},
		{"bearer with an empty token", []string{"Bearer "}},
		{"wrong token", []string{"Bearer " + testMetricsToken + "x"}},
		{"token a character short", []string{"Bearer " + testMetricsToken[1:]}},
		{"token in another case", []string{"Bearer " + strings.ToUpper(testMetricsToken)}},
		{"a personal API token", []string{"Bearer prt_abcdefghijklmnopqrstuv_" + strings.Repeat("A", 52)}},
		{"two headers, the right one first", []string{"Bearer " + testMetricsToken, "Bearer " + testMetricsToken}},
		{"two headers, the wrong one first", []string{"Bearer wrong", "Bearer " + testMetricsToken}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEnv(t, withMetrics(testMetricsToken))
			res := e.client("10.0.0.1:1").scrape(tt.auth...)
			if res.Code != http.StatusUnauthorized || res.errorCode() != "invalid_token" {
				t.Fatalf("status %d, code %q; want 401 invalid_token", res.Code, res.errorCode())
			}
			if got := res.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
				t.Errorf("WWW-Authenticate = %q", got)
			}
			if strings.Contains(res.Body.String(), "test_scrapes_total") {
				t.Error("the metrics leaked into a refusal")
			}
			if strings.Contains(res.Body.String(), testMetricsToken) {
				t.Error("the refusal repeats the token")
			}
		})
	}
}

func TestMetricsIgnoresSessionsAndCookies(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken))
	e.addUser("admin", "admin-password-1", true)
	c := e.client("10.0.0.1:1")
	if res := c.login("admin", "admin-password-1"); res.Code != http.StatusOK {
		t.Fatalf("login: %d", res.Code)
	}
	if res := c.scrape(); res.Code != http.StatusUnauthorized {
		t.Fatalf("an admin's session opened /metrics: %d", res.Code)
	}
}

func TestMetricsTokenOpensNothingElse(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken))
	c := e.client("10.0.0.1:1")
	for _, path := range []string{"/api/v1/targets", "/api/v1/audit", "/api/v1/system/secrets", "/api/v1/auth/session"} {
		r := c.request(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+testMetricsToken)
		if res := c.send(r); res.Code != http.StatusUnauthorized || res.errorCode() != "invalid_token" {
			t.Errorf("GET %s with the metrics token: %d %q, want 401 invalid_token", path, res.Code, res.errorCode())
		}
	}
}

func TestMetricsWrongTokensHaveALimiterOfTheirOwn(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken), withLimits)
	e.addUser("admin", "admin-password-1", true)
	c := e.client("10.0.0.1:1")

	// The right token never counts, however often a scraper comes.
	for i := 0; i < 10; i++ {
		if res := c.scrape("Bearer " + testMetricsToken); res.Code != http.StatusOK {
			t.Fatalf("scrape %d: %d", i, res.Code)
		}
	}
	for i := 0; i < 3; i++ {
		if res := c.scrape("Bearer wrong"); res.Code != http.StatusUnauthorized {
			t.Fatalf("wrong token %d: %d, want 401", i, res.Code)
		}
	}
	// The address has used its allowance: even the right token waits.
	res := c.scrape("Bearer " + testMetricsToken)
	if res.Code != http.StatusTooManyRequests || res.errorCode() != "rate_limited" {
		t.Fatalf("after the limit: %d %q, want 429 rate_limited", res.Code, res.errorCode())
	}
	if got := res.Header().Get("Retry-After"); got == "" || got == "0" {
		t.Errorf("Retry-After = %q", got)
	}

	// Another address is unaffected.
	if res := e.client("10.0.0.2:1").scrape("Bearer " + testMetricsToken); res.Code != http.StatusOK {
		t.Errorf("another address: %d", res.Code)
	}
	// And the same address can still log in: the login limiters never saw those failures.
	if res := c.login("admin", "admin-password-1"); res.Code != http.StatusOK {
		t.Fatalf("login from the limited address: %d %s", res.Code, res.Body)
	}
}

func TestLoginFailuresDontLimitMetrics(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken), withLimits)
	c := e.client("10.0.0.1:1")
	for i := 0; i < 6; i++ {
		c.login("nobody", "wrong-password")
	}
	if res := c.scrape("Bearer " + testMetricsToken); res.Code != http.StatusOK {
		t.Fatalf("scrape from an address with failed logins: %d", res.Code)
	}
}

func TestMetricsLimiterIsPerClientAddressBehindATrustedProxy(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken), withTrustedProxy("10.0.0.0/24"))
	proxy := e.client("10.0.0.2:1")
	proxy.xff = "192.0.2.9"
	for i := 0; i < 3; i++ {
		proxy.scrape("Bearer wrong")
	}
	if res := proxy.scrape("Bearer " + testMetricsToken); res.Code != http.StatusTooManyRequests {
		t.Fatalf("the forwarded address: %d, want 429", res.Code)
	}
	other := e.client("10.0.0.2:1")
	other.xff = "192.0.2.10"
	if res := other.scrape("Bearer " + testMetricsToken); res.Code != http.StatusOK {
		t.Fatalf("another forwarded address: %d, want 200", res.Code)
	}
}

func TestMetricsTokenChangeNeedsOnlyAReload(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "metrics-token")
	first, second := testMetricsToken, "another-token-0123456789-abcdefghijklmn"
	if err := os.WriteFile(f, []byte(first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, func(o *Options) {
		withMetrics("")(o)
		sec, err := secrets.Load(secrets.Options{
			DataDir: dir,
			Getenv: func(k string) string {
				if k == secrets.VarMetricsToken+"_FILE" {
					return f
				}
				return ""
			},
			Environ: func() []string { return nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Secrets = sec
		o.MetricsByIP = nil
	})
	c := e.client("10.0.0.1:1")
	if res := c.scrape("Bearer " + first); res.Code != http.StatusOK {
		t.Fatalf("before: %d", res.Code)
	}
	if err := os.WriteFile(f, []byte(second+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := c.scrape("Bearer " + first); res.Code != http.StatusOK {
		t.Fatalf("a file changed on disk took effect without a reload: %d", res.Code)
	}
	e.srv.Secrets.Reload()
	if res := c.scrape("Bearer " + first); res.Code != http.StatusUnauthorized {
		t.Errorf("the old token after a reload: %d, want 401", res.Code)
	}
	if res := c.scrape("Bearer " + second); res.Code != http.StatusOK {
		t.Errorf("the new token after a reload: %d, want 200", res.Code)
	}
}

func TestMetricsTokenIsListedWithoutItsValue(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken))
	e.addUser("admin", "admin-password-1", true)
	c := e.client("10.0.0.1:1")
	c.login("admin", "admin-password-1")
	res := c.do(http.MethodGet, "/api/v1/system/secrets", nil)
	if res.Code != http.StatusOK {
		t.Fatalf("status %d: %s", res.Code, res.Body)
	}
	if strings.Contains(res.Body.String(), testMetricsToken) {
		t.Fatal("the secrets list holds the token")
	}
	var body struct{ Secrets []gen.SecretStatus }
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, s := range body.Secrets {
		if s.Name == secrets.VarMetricsToken {
			if s.Kind != gen.SecretStatusKindMetricsToken || !s.Set || s.Source == nil || *s.Source != "env" {
				t.Errorf("listed as %+v", s)
			}
			return
		}
	}
	t.Fatal("the metrics token isn't in the secrets list")
}

func TestMetricsWithoutARegistryIsEmpty(t *testing.T) {
	e := newTestEnv(t, withMetrics(testMetricsToken), func(o *Options) { o.MetricsRegistry = nil })
	res := e.client("10.0.0.1:1").scrape("Bearer " + testMetricsToken)
	if res.Code != http.StatusOK || res.Body.Len() != 0 {
		t.Fatalf("status %d, %d bytes; want 200 and nothing", res.Code, res.Body.Len())
	}
}
