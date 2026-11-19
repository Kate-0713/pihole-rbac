// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package appmetrics

import (
	"context"
	"database/sql"
	"errors"
	"github.com/Kate-0713/pihole-rbac/internal/metrics/metricstest"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/logdestinations"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const password = "pihole app password"

type passwords struct{}

func (passwords) Cipher() *secrets.Cipher { return nil }
func (passwords) InstancePassword(string) (secrets.Value, bool) {
	return secrets.NewValue([]byte(password)), true
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type env struct {
	reg  *metrics.Registry
	clk  *clock
	errs []error
}

func newEnv(t *testing.T, mod func(*Sources)) *env {
	t.Helper()
	e := &env{reg: metrics.New(), clk: &clock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}}
	e.reg.ErrorFunc = func(err error) { e.errs = append(e.errs, err) }
	s := Sources{Now: e.clk.now}
	mod(&s)
	Register(e.reg, s)
	return e
}

func (e *env) scrape(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if _, err := e.reg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func want(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l) {
			t.Errorf("missing %q in:\n%s", l, out)
		}
	}
}

func absent(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, l := range subs {
		if strings.Contains(out, l) {
			t.Errorf("unexpected %q in:\n%s", l, out)
		}
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestInstanceSeries(t *testing.T) {
	ctx := context.Background()
	pool := instances.New(instances.Options{Passwords: passwords{}, Timeout: 2 * time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(func() { pool.Close(ctx) })
	up := piholetest.New(t, password)
	down := piholetest.New(t, "another password")
	mk := func(id int64, name, url string) instances.Instance {
		return instances.Instance{ID: id, Name: name, BaseURL: url, EnvName: "X", TLSMode: piholeapi.TLSVerify, Enabled: true}
	}
	pool.Put(mk(1, "alpha", up.URL))
	pool.Put(mk(2, "beta", down.URL))
	pool.Put(mk(3, "gamma", up.URL)) // never called
	off := mk(4, "delta", up.URL)
	off.Enabled = false
	pool.Put(off)

	e := newEnv(t, func(s *Sources) { s.Pool = pool })
	// Nothing has been called: no series at all, not zeros.
	out := e.scrape(t)
	absent(t, out, "pihole_rbac_instance_up{", "instance_last_success_timestamp_seconds{")

	_ = pool.Do(ctx, 1, func(ctx context.Context, c *piholeapi.Client) error { _, err := c.GetStatus(ctx); return err })
	_ = pool.Do(ctx, 2, func(ctx context.Context, c *piholeapi.Client) error { _, err := c.GetStatus(ctx); return err })
	out = e.scrape(t)
	want(t, out, `pihole_rbac_instance_up{instance="alpha"} 1`, `pihole_rbac_instance_up{instance="beta"} 0`,
		`pihole_rbac_instance_last_success_timestamp_seconds{instance="alpha"} `)
	absent(t, out, `instance="gamma"`, `instance="delta"`, `last_success_timestamp_seconds{instance="beta"}`)
	metricstest.Dump(t, e.reg)
}

func TestDriftSeries(t *testing.T) {
	groups := []instances.Group{
		{ID: 1, Name: "site", Mode: rbac.Mirrored},
		{ID: 2, Name: "fresh", Mode: rbac.Mirrored},
		{ID: 3, Name: "broken", Mode: rbac.Mirrored},
		{ID: 4, Name: "loose", Mode: rbac.Independent},
	}
	checked := time.Date(2026, 11, 19, 11, 59, 0, 0, time.UTC)
	reports := map[int64]instances.Report{
		1: {GroupID: 1, CheckedAt: checked, PrimaryOK: true, Domains: make([]instances.DomainDrift, 2), LocalDNS: make([]instances.LocalDNSDrift, 1)},
		3: {GroupID: 3, CheckedAt: checked, PrimaryOK: false},
		4: {GroupID: 4, CheckedAt: checked, PrimaryOK: true},
	}
	e := newEnv(t, func(s *Sources) {
		s.Groups = func(context.Context) ([]instances.Group, error) { return groups, nil }
		s.Report = func(id int64) (instances.Report, bool) { r, ok := reports[id]; return r, ok }
	})
	out := e.scrape(t)
	want(t, out,
		`pihole_rbac_group_drift_items{group="site",type="domains"} 2`,
		`pihole_rbac_group_drift_items{group="site",type="clients"} 0`,
		`pihole_rbac_group_drift_items{group="site",type="local_dns"} 1`,
		`pihole_rbac_group_drift_last_check_timestamp_seconds{group="site"} `+formatFloat(float64(checked.Unix())),
		`pihole_rbac_group_drift_last_check_timestamp_seconds{group="broken"} `,
	)
	// Not checked yet, primary unreadable and not mirrored: no differences are claimed.
	absent(t, out, `drift_items{group="fresh"`, `drift_items{group="broken"`, `group="loose"`, `group="fresh"`)
	metricstest.Dump(t, e.reg)
}

func TestGroupsFailureIsLoggedAndLeavesOtherSeries(t *testing.T) {
	e := newEnv(t, func(s *Sources) {
		s.Groups = func(context.Context) ([]instances.Group, error) { return nil, errors.New("database is locked") }
		s.Report = func(int64) (instances.Report, bool) { return instances.Report{}, false }
		s.QueueLength = func() int { return 4 }
	})
	out := e.scrape(t)
	want(t, out, `pihole_rbac_notification_queue_length 4`)
	absent(t, out, "drift")
	if len(e.errs) != 1 || !strings.Contains(e.errs[0].Error(), "database is locked") {
		t.Errorf("errors %v", e.errs)
	}
}

func TestReadsAreCached(t *testing.T) {
	var calls atomic.Int32
	e := newEnv(t, func(s *Sources) {
		s.Destinations = func(context.Context) ([]logdestinations.Destination, error) {
			calls.Add(1)
			return []logdestinations.Destination{
				{Name: "Main", Enabled: true, Status: logdestinations.Status{Behind: 7}},
				{Name: "Old", Enabled: false, Status: logdestinations.Status{Behind: 900}},
			}, nil
		}
	})
	for range 5 {
		e.scrape(t)
	}
	if calls.Load() != 1 {
		t.Errorf("%d reads for 5 scrapes inside the interval, want 1", calls.Load())
	}
	e.clk.t = e.clk.t.Add(DefaultCacheFor)
	out := e.scrape(t)
	if calls.Load() != 2 {
		t.Errorf("%d reads after the interval, want 2", calls.Load())
	}
	want(t, out, `pihole_rbac_log_forward_behind{destination="Main"} 7`)
	absent(t, out, `destination="Old"`) // disabled ones fall behind for ever and say nothing
}

func TestSlowReadIsCutOff(t *testing.T) {
	e := newEnv(t, func(s *Sources) {
		s.Timeout = 20 * time.Millisecond
		s.Destinations = func(ctx context.Context) ([]logdestinations.Destination, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
	})
	began := time.Now()
	out := e.scrape(t)
	if time.Since(began) > 2*time.Second {
		t.Error("a slow read held the scrape up")
	}
	absent(t, out, "log_forward_behind")
	if len(e.errs) != 1 || !errors.Is(e.errs[0], context.DeadlineExceeded) {
		t.Errorf("errors %v", e.errs)
	}
}

func TestUpdateAvailable(t *testing.T) {
	for _, tc := range []struct {
		name             string
		known, available bool
		want, absent     string
	}{
		{"newer release", true, true, "pihole_rbac_update_available 1", ""},
		{"up to date", true, false, "pihole_rbac_update_available 0", ""},
		{"check off or nothing found", false, false, "", "pihole_rbac_update_available"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(s *Sources) {
				s.Update = func(context.Context) (bool, bool, error) { return tc.known, tc.available, nil }
			})
			out := e.scrape(t)
			if tc.want != "" {
				want(t, out, tc.want)
			}
			if tc.absent != "" {
				absent(t, out, tc.absent)
			}
		})
	}
}

func TestSessionsAndClientResetFromTheDatabase(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	ms := store.Millis
	var instA, instB, groupG int64
	err := st.WithTx(ctx, func(q *db.Queries) error {
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: "u", PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: ms(now)})
		if err != nil {
			return err
		}
		// live; expired; idle
		for i, c := range []struct{ expires, seen time.Time }{
			{now.Add(time.Hour), now.Add(-time.Minute)},
			{now.Add(-time.Second), now.Add(-time.Minute)},
			{now.Add(time.Hour), now.Add(-2 * time.Hour)},
		} {
			id := make([]byte, 32)
			id[0] = byte(i + 1)
			if err := q.CreateSession(ctx, db.CreateSessionParams{
				IDHash: id, PublicID: strings.Repeat(string(rune('a'+i)), 22), UserID: u.ID,
				CreatedAt: ms(now.Add(-3 * time.Hour)), ExpiresAt: ms(c.expires), LastSeenAt: ms(c.seen), RolesCheckedAt: ms(now),
			}); err != nil {
				return err
			}
		}
		mk := func(name string) (int64, error) {
			return q.CreateInstance(ctx, db.CreateInstanceParams{Name: name, BaseUrl: "https://" + name + ".example", TlsMode: "verify", CreatedAt: ms(now)})
		}
		if instA, err = mk("alpha"); err != nil {
			return err
		}
		if instB, err = mk("beta"); err != nil {
			return err
		}
		if groupG, err = q.CreateInstanceGroup(ctx, db.CreateInstanceGroupParams{Name: "site", Mode: "independent", CreatedAt: ms(now)}); err != nil {
			return err
		}
		run := func(target string, inst, grp sql.NullInt64, name, status string, finished time.Time) error {
			id, err := q.StartClientResetRun(ctx, db.StartClientResetRunParams{
				StartedAt: ms(finished.Add(-time.Minute)), Trigger: "manual", Username: "u", Target: target, InstanceID: inst, GroupID: grp, TargetName: name,
			})
			if err != nil {
				return err
			}
			return q.FinishClientResetRun(ctx, db.FinishClientResetRunParams{FinishedAt: sql.NullInt64{Int64: ms(finished), Valid: true}, Status: status, Summary: "{}", ID: id})
		}
		i := func(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
		// alpha: an old failure then a newer success, so only the success counts; beta: a partial; the group: ok.
		if err := run("i-1", i(instA), sql.NullInt64{}, "alpha", "failed", now.Add(-3*time.Hour)); err != nil {
			return err
		}
		if err := run("i-1", i(instA), sql.NullInt64{}, "alpha", "ok", now.Add(-2*time.Hour)); err != nil {
			return err
		}
		if err := run("i-2", i(instB), sql.NullInt64{}, "beta", "partial", now.Add(-time.Hour)); err != nil {
			return err
		}
		return run("g-1", sql.NullInt64{}, i(groupG), "site", "ok", now.Add(-30*time.Minute))
	})
	if err != nil {
		t.Fatal(err)
	}
	// A run for a target that has since been deleted leaves nothing behind.
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		id, err := q.StartClientResetRun(ctx, db.StartClientResetRunParams{StartedAt: ms(now), Trigger: "manual", Username: "u", Target: "i-9", TargetName: "gone"})
		if err != nil {
			return err
		}
		return q.FinishClientResetRun(ctx, db.FinishClientResetRunParams{FinishedAt: sql.NullInt64{Int64: ms(now), Valid: true}, Status: "ok", Summary: "{}", ID: id})
	}); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t, func(s *Sources) {
		s.Store = st
		s.Lifetimes = func() (time.Duration, time.Duration) { return 24 * time.Hour, time.Hour }
	})
	out := e.scrape(t)
	want(t, out,
		`pihole_rbac_sessions_active 1`,
		`pihole_rbac_client_reset_last_run_ok{target_type="instance",target="alpha"} 1`,
		`pihole_rbac_client_reset_last_run_ok{target_type="instance",target="beta"} 0`,
		`pihole_rbac_client_reset_last_run_ok{target_type="group",target="site"} 1`,
	)
	absent(t, out, `target="gone"`)
	// alpha's timestamp is the success two hours ago, not the failure before it.
	wantTS := float64(now.Add(-2 * time.Hour).Unix())
	if !strings.Contains(out, `pihole_rbac_client_reset_last_run_timestamp_seconds{target_type="instance",target="alpha"} `+formatFloat(wantTS)) {
		t.Errorf("alpha's timestamp is wrong:\n%s", out)
	}
	metricstest.Dump(t, e.reg)
}

// formatFloat is how the exposition writer prints a whole number of seconds.
func formatFloat(f float64) string { return strconv.FormatInt(int64(f), 10) }

func TestNothingRegisteredWithoutSources(t *testing.T) {
	Register(nil, Sources{}) // a nil registry is fine
	e := newEnv(t, func(*Sources) {})
	if out := e.scrape(t); strings.Contains(out, "pihole_rbac_") {
		t.Errorf("series from nothing:\n%s", out)
	}
}
