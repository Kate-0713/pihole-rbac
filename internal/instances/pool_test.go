// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

const password = "pihole app password"

type fakePasswords struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakePasswords) InstancePassword(env string) (secrets.Value, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[env]
	return secrets.NewValue([]byte(v)), ok && v != ""
}

func (f *fakePasswords) set(env, pw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[env] = pw
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newPool(t *testing.T) (*Pool, *fakePasswords, *clock) {
	t.Helper()
	pw := &fakePasswords{m: map[string]string{"PIHOLE1": password, "PIHOLE2": password}}
	clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	p := New(Options{Passwords: pw, Timeout: 2 * time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	p.now = clk.now
	t.Cleanup(func() { p.Close(context.Background()) })
	return p, pw, clk
}

func inst(id int64, env, url string) Instance {
	return Instance{ID: id, Name: strings.ToLower(env), BaseURL: url, EnvName: env, TLSMode: piholeapi.TLSVerify, Enabled: true}
}

func status(ctx context.Context, c *piholeapi.Client) error {
	_, err := c.GetStatus(ctx)
	return err
}

// countingDown is a Pi-hole that refuses every login and counts the attempts.
func countingDown(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"session":{"valid":false}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestDoRecordsHealth(t *testing.T) {
	ctx := context.Background()
	p, _, clk := newPool(t)
	up := piholetest.New(t, password)
	up.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/api/domains" {
			http.Error(w, "nope", http.StatusBadRequest)
			return true
		}
		return false
	})
	p.Put(inst(1, "PIHOLE1", up.URL))

	if h, _ := p.Health(1); h.State != StateUnknown {
		t.Fatalf("before any call: %+v, want unknown", h)
	}
	if err := p.Do(ctx, 1, status); err != nil {
		t.Fatal(err)
	}
	h, _ := p.Health(1)
	if h.State != StateUp || !h.LastSuccess.Equal(clk.now()) || h.LastError != "" {
		t.Fatalf("after success: %+v", h)
	}

	// A refused request means Pi-hole is up: no backoff, the error code is kept.
	clk.advance(time.Second)
	err := p.Do(ctx, 1, func(ctx context.Context, c *piholeapi.Client) error {
		_, err := c.ListDomains(ctx)
		return err
	})
	if Kind(err) != piholeapi.CodeStatusError {
		t.Fatalf("ListDomains: %v", err)
	}
	h, _ = p.Health(1)
	if h.State != StateUp || h.LastError != piholeapi.CodeStatusError || !h.LastFailure.Equal(clk.now()) {
		t.Fatalf("after a refused request: %+v", h)
	}
	if err := p.Do(ctx, 1, status); err != nil {
		t.Fatalf("call after a refused request: %v", err)
	}
}

func TestDownInstanceBacksOff(t *testing.T) {
	ctx := context.Background()
	p, _, clk := newPool(t)
	down, hits := countingDown(t)
	up := piholetest.New(t, password)
	p.Put(inst(1, "PIHOLE1", down.URL))
	p.Put(inst(2, "PIHOLE2", up.URL))

	err := p.Do(ctx, 1, status)
	if !errors.Is(err, piholeapi.ErrAuthRejected) {
		t.Fatalf("first call: %v", err)
	}
	if h, _ := p.Health(1); h.State != StateDown || h.LastError != piholeapi.CodeAuthRejected {
		t.Fatalf("health: %+v", h)
	}

	clk.advance(DefaultBackoff - time.Second)
	if err := p.Do(ctx, 1, status); !errors.Is(err, piholeapi.ErrAuthRejected) {
		t.Fatalf("call in backoff: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("Pi-hole was called %d times during the backoff, want 1", n)
	}
	// The other instance is unaffected.
	if err := p.Do(ctx, 2, status); err != nil {
		t.Fatalf("other instance: %v", err)
	}

	clk.advance(2 * time.Second)
	_ = p.Do(ctx, 1, status)
	if n := hits.Load(); n != 2 {
		t.Fatalf("after the backoff Pi-hole was called %d times in total, want 2", n)
	}
}

func TestDoErrors(t *testing.T) {
	ctx := context.Background()
	p, pw, _ := newPool(t)
	up := piholetest.New(t, password)
	pw.set("NOPASS", "")

	p.Put(inst(1, "NOPASS", up.URL))
	bad := inst(2, "PIHOLE1", up.URL)
	bad.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	p.Put(bad)
	disabled := inst(3, "PIHOLE2", up.URL)
	disabled.Enabled = false
	p.Put(disabled)

	tests := []struct {
		name     string
		id       int64
		wantIs   error
		wantKind string
		wantText string
	}{
		{"password missing", 1, ErrNoPassword, CodePasswordMissing, "PIHOLE_RBAC_INSTANCE_NOPASS_PASSWORD"},
		{"misconfigured", 2, ErrMisconfigured, CodeMisconfigured, "CA file"},
		{"disabled", 3, ErrNotFound, "", ""},
		{"unknown", 99, ErrNotFound, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			err := p.Do(ctx, tt.id, func(context.Context, *piholeapi.Client) error { called = true; return nil })
			if called {
				t.Error("fn was called")
			}
			if !errors.Is(err, tt.wantIs) || Kind(err) != tt.wantKind || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("err = %v (kind %q), want %v, kind %q, text %q", err, Kind(err), tt.wantIs, tt.wantKind, tt.wantText)
			}
			if tt.wantKind != "" {
				if h, _ := p.Health(tt.id); h.State != StateDown || h.LastError != tt.wantKind {
					t.Errorf("health %+v", h)
				}
			}
		})
	}
}

func TestCancelledCallLeavesHealthAlone(t *testing.T) {
	p, _, _ := newPool(t)
	up := piholetest.New(t, password)
	p.Put(inst(1, "PIHOLE1", up.URL))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Do(ctx, 1, status); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if h, _ := p.Health(1); h.State != StateUnknown || !h.LastFailure.IsZero() {
		t.Fatalf("health %+v, want untouched", h)
	}
}

func TestPutKeepsOrReplacesClient(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPool(t)
	a := piholetest.New(t, password)
	b := piholetest.New(t, password)
	i := inst(1, "PIHOLE1", a.URL)
	p.Put(i)
	if err := p.Do(ctx, 1, status); err != nil {
		t.Fatal(err)
	}

	i.Name = "renamed"
	if p.Put(i) {
		t.Error("a rename rebuilt the client")
	}
	if err := p.Do(ctx, 1, status); err != nil {
		t.Fatal(err)
	}
	if a.Logins() != 1 {
		t.Errorf("logins after rename = %d, want 1 (session kept)", a.Logins())
	}

	i.BaseURL = b.URL
	if !p.Put(i) {
		t.Error("a new base URL didn't rebuild the client")
	}
	p.retiring.Wait()
	if a.Sessions() != 0 || a.Logouts() != 1 {
		t.Errorf("old Pi-hole: %d sessions, %d logouts; want 0 and 1", a.Sessions(), a.Logouts())
	}
	if h, _ := p.Health(1); h.State != StateUnknown {
		t.Errorf("health after rebuild %+v, want reset", h)
	}
	if err := p.Do(ctx, 1, status); err != nil || b.Logins() != 1 {
		t.Fatalf("new Pi-hole: err %v, logins %d", err, b.Logins())
	}

	i.Enabled = false
	p.Put(i)
	p.retiring.Wait()
	if b.Sessions() != 0 {
		t.Error("disabling didn't log out")
	}
	if err := p.Do(ctx, 1, status); !errors.Is(err, ErrNotFound) {
		t.Errorf("after disabling: %v", err)
	}
}

// An instance edited while a call is in flight closes the client that call holds; the call is retried once on the
// new client.
func TestDoRetriesOnReplacedClient(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPool(t)
	a := piholetest.New(t, password)
	b := piholetest.New(t, password)
	i := inst(1, "PIHOLE1", a.URL)
	p.Put(i)

	calls := 0
	err := p.Do(ctx, 1, func(ctx context.Context, c *piholeapi.Client) error {
		calls++
		if calls == 1 {
			i.BaseURL = b.URL
			p.Put(i)
			p.retiring.Wait()
		}
		return status(ctx, c)
	})
	if err != nil || calls != 2 {
		t.Fatalf("err %v after %d calls; want nil after 2", err, calls)
	}
	if h, _ := p.Health(1); h.State != StateUp {
		t.Errorf("health %+v", h)
	}
}

func TestReloadPasswords(t *testing.T) {
	ctx := context.Background()
	p, pw, _ := newPool(t)
	a := piholetest.New(t, "new password")
	b := piholetest.New(t, password)
	p.Load([]Instance{inst(1, "PIHOLE1", a.URL), inst(2, "PIHOLE2", b.URL)})

	if err := p.Do(ctx, 1, status); !errors.Is(err, piholeapi.ErrAuthRejected) {
		t.Fatalf("before reload: %v", err)
	}
	if err := p.Do(ctx, 2, status); err != nil {
		t.Fatal(err)
	}

	pw.set("PIHOLE1", "new password")
	got := p.ReloadPasswords()
	if len(got) != 1 || got[0] != "pihole1" {
		t.Fatalf("rebuilt %v, want [pihole1]", got)
	}
	// The rebuilt instance isn't held back by the old client's backoff.
	if err := p.Do(ctx, 1, status); err != nil {
		t.Fatalf("after reload: %v", err)
	}
	if err := p.Do(ctx, 2, status); err != nil || b.Logins() != 1 {
		t.Fatalf("unchanged instance: err %v, logins %d (want session kept)", err, b.Logins())
	}
	if got := p.ReloadPasswords(); len(got) != 0 {
		t.Errorf("second reload rebuilt %v", got)
	}
}

func TestLoadRemovesMissing(t *testing.T) {
	p, _, _ := newPool(t)
	up := piholetest.New(t, password)
	p.Load([]Instance{inst(1, "PIHOLE1", up.URL), inst(2, "PIHOLE2", up.URL)})
	p.Load([]Instance{inst(2, "PIHOLE2", up.URL)})
	if _, ok := p.Health(1); ok {
		t.Error("instance 1 is still in the pool")
	}
	if _, ok := p.Health(2); !ok {
		t.Error("instance 2 is missing")
	}
}

func TestProbe(t *testing.T) {
	ctx := context.Background()
	p, _, clk := newPool(t)
	down, hits := countingDown(t)
	up := piholetest.New(t, password)
	p.Load([]Instance{inst(1, "PIHOLE1", down.URL), inst(2, "PIHOLE2", up.URL)})

	p.Probe(ctx)
	if h, _ := p.Health(1); h.State != StateDown {
		t.Errorf("down instance: %+v", h)
	}
	if h, _ := p.Health(2); h.State != StateUp {
		t.Errorf("up instance: %+v", h)
	}

	// Recently checked instances aren't probed again.
	clk.advance(DefaultProbeInterval / 2)
	p.Probe(ctx)
	if n := hits.Load(); n != 1 {
		t.Errorf("probed again too soon: %d calls", n)
	}

	// The probe ignores the backoff, so a recovered instance is noticed.
	clk.advance(DefaultProbeInterval)
	p.Probe(ctx)
	if n := hits.Load(); n != 2 {
		t.Errorf("idle instance not probed: %d calls", n)
	}
}

func TestTest(t *testing.T) {
	ctx := context.Background()
	p, pw, _ := newPool(t)
	up := piholetest.New(t, password)
	pw.set("WRONG", "not it")

	if err := p.Test(ctx, inst(1, "PIHOLE1", up.URL)); err != nil {
		t.Errorf("good settings: %v", err)
	}
	if up.Sessions() != 0 {
		t.Error("Test left a session open")
	}
	if err := p.Test(ctx, inst(1, "WRONG", up.URL)); !errors.Is(err, piholeapi.ErrAuthRejected) {
		t.Errorf("wrong password: %v", err)
	}
	if err := p.Test(ctx, inst(1, "UNSET", up.URL)); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	if err := p.Test(ctx, inst(1, "PIHOLE1", "pi.hole")); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("bad URL: %v", err)
	}
	if _, ok := p.Health(1); ok {
		t.Error("Test added the instance to the pool")
	}
}

func TestCloseLogsOutEverything(t *testing.T) {
	ctx := context.Background()
	p, _, _ := newPool(t)
	up := piholetest.New(t, password)
	p.Load([]Instance{inst(1, "PIHOLE1", up.URL), inst(2, "PIHOLE2", up.URL)})
	_ = p.Do(ctx, 1, status)
	_ = p.Do(ctx, 2, status)
	if up.Sessions() != 2 {
		t.Fatalf("sessions = %d", up.Sessions())
	}
	p.Close(ctx)
	if up.Sessions() != 0 {
		t.Errorf("sessions after Close = %d", up.Sessions())
	}
	p.Put(inst(1, "PIHOLE1", up.URL))
	if err := p.Do(ctx, 1, status); !errors.Is(err, ErrNotFound) {
		t.Errorf("Put after Close: %v", err)
	}
}
