// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func currentSession(t *testing.T, c *client) gen.CurrentSession {
	t.Helper()
	return decode[gen.CurrentSession](t, c.do(http.MethodGet, "/api/v1/auth/session", nil))
}

func sessionIDs(l gen.SessionList) []string {
	var out []string
	for _, s := range l.Sessions {
		out = append(out, s.PublicId)
	}
	return out
}

func TestListSessions(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)
	alice := []*client{e.loggedIn("alice", "alice-password-1"), e.loggedIn("alice", "alice-password-1"), e.loggedIn("alice", "alice-password-1")}
	e.loggedIn("bob", "bob-password-123")
	admin := e.loggedIn("admin", "admin-password-1")

	own := decode[gen.SessionList](t, alice[0].do(http.MethodGet, "/api/v1/sessions", nil))
	if own.All || len(own.Sessions) != 3 || own.NextCursor != nil {
		t.Fatalf("alice's own: %+v", own)
	}
	for _, s := range own.Sessions {
		if s.User.Username != "alice" || s.Current != (s.PublicId == currentSession(t, alice[0]).PublicId) {
			t.Errorf("session %+v", s)
		}
	}
	if !own.Sessions[0].CreatedAt.After(own.Sessions[2].CreatedAt) && !own.Sessions[0].CreatedAt.Equal(own.Sessions[2].CreatedAt) {
		t.Error("not newest first")
	}

	everyone := decode[gen.SessionList](t, admin.do(http.MethodGet, "/api/v1/sessions", nil))
	if !everyone.All || len(everyone.Sessions) != 5 {
		t.Errorf("admin sees %d sessions, all=%v", len(everyone.Sessions), everyone.All)
	}
	mine := decode[gen.SessionList](t, admin.do(http.MethodGet, "/api/v1/sessions?mine=true", nil))
	if mine.All || len(mine.Sessions) != 1 || !mine.Sessions[0].Current {
		t.Errorf("admin's own: %+v", mine)
	}

	// Pages of two cover everything once.
	var seen []string
	path := "/api/v1/sessions?limit=2"
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("paging doesn't end")
		}
		page := decode[gen.SessionList](t, admin.do(http.MethodGet, path, nil))
		seen = append(seen, sessionIDs(page)...)
		if page.NextCursor == nil {
			break
		}
		path = "/api/v1/sessions?limit=2&cursor=" + *page.NextCursor
	}
	slices.Sort(seen)
	want := sessionIDs(everyone)
	slices.Sort(want)
	if !slices.Equal(seen, want) {
		t.Errorf("paged %v, want %v", seen, want)
	}

	for _, bad := range []string{"?limit=0", "?limit=201", "?cursor=nonsense", "?cursor=MTox"} {
		if res := admin.do(http.MethodGet, "/api/v1/sessions"+bad, nil); res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, res.Code, res.Body)
		}
	}
	mustStatus(t, e.client("10.0.0.9:1").do(http.MethodGet, "/api/v1/sessions", nil), http.StatusUnauthorized)
}

func TestRevokeSession(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("alice", "alice-password-1", rbac.DomainsView)
	e.addRoleUser("bob", "bob-password-123", rbac.DomainsView)
	here, there := e.loggedIn("alice", "alice-password-1"), e.loggedIn("alice", "alice-password-1")
	bob := e.loggedIn("bob", "bob-password-123")
	admin := e.loggedIn("admin", "admin-password-1")
	revoke := func(c *client, id string) response { return c.do(http.MethodDelete, "/api/v1/sessions/"+id, nil) }

	// Your own other session: ended.
	mustStatus(t, revoke(here, currentSession(t, there).PublicId), http.StatusNoContent)
	mustStatus(t, there.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)

	// Someone else's, without sessions.manage: not found, the same as one that doesn't exist, and nothing happens.
	bobID := currentSession(t, bob).PublicId
	for _, id := range []string{bobID, "AAAAAAAAAAAAAAAAAAAAAA", "not-a-session-id"} {
		if res := revoke(here, id); res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
			t.Errorf("revoking %s: %d %s", id, res.Code, res.Body)
		}
	}
	mustStatus(t, bob.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// With sessions.manage, anyone's.
	mustStatus(t, revoke(admin, bobID), http.StatusNoContent)
	mustStatus(t, bob.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)

	// Your current session: logged out, cookie cleared.
	res := revoke(here, currentSession(t, here).PublicId)
	mustStatus(t, res, http.StatusNoContent)
	if ck := res.cookie(auth.SessionCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("cookie not cleared: %+v", ck)
	}
	mustStatus(t, here.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized)

	var targets []string
	for _, r := range e.auditRows() {
		if r.Action == "session_revoke" {
			targets = append(targets, r.Target)
		}
	}
	if !slices.Equal(targets, []string{"user:alice", "user:bob", "user:alice"}) {
		t.Errorf("session_revoke rows: %v", targets)
	}
}

func TestGeneralSettings(t *testing.T) {
	var svc *loginsettings.Service
	e := newTestEnv(t, func(o *Options) {
		svc = &loginsettings.Service{
			Store: o.Store, Audit: o.Audit, Secrets: testSecrets{}, Sessions: o.Sessions,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if err := svc.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		o.LoginSettings = svc
	})
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("viewer", "viewer-password", rbac.DomainsView)
	c := e.loggedIn("admin", "admin-password-1")

	g := decode[gen.GeneralSettings](t, c.do(http.MethodGet, "/api/v1/settings/general", nil))
	if g.SessionLifetimeMinutes != 480 || g.IdleTimeoutMinutes != 60 || g.UpdatedAt != nil {
		t.Errorf("defaults: %+v", g)
	}
	for _, bad := range []gen.GeneralSettingsInput{
		{SessionLifetimeMinutes: 10, IdleTimeoutMinutes: 5},
		{SessionLifetimeMinutes: 60, IdleTimeoutMinutes: 2},
		{SessionLifetimeMinutes: 30, IdleTimeoutMinutes: 60},
		{SessionLifetimeMinutes: 50000, IdleTimeoutMinutes: 60},
	} {
		if res := c.do(http.MethodPut, "/api/v1/settings/general", bad); res.Code != http.StatusBadRequest {
			t.Errorf("%+v: %d %s", bad, res.Code, res.Body)
		}
	}
	res := c.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{SessionLifetimeMinutes: 120, IdleTimeoutMinutes: 30})
	mustStatus(t, res, http.StatusOK)
	if g := decode[gen.GeneralSettings](t, res); g.SessionLifetimeMinutes != 120 || g.UpdatedBy == nil || *g.UpdatedBy != "admin" {
		t.Errorf("saved: %+v", g)
	}
	if l, i := e.srv.Sessions.Lifetimes(); l != 2*time.Hour || i != 30*time.Minute {
		t.Errorf("sessions use %v and %v", l, i)
	}
	// A session started now ends two hours from now.
	s := currentSession(t, e.loggedIn("admin", "admin-password-1"))
	if d := time.Until(s.ExpiresAt); d > 2*time.Hour || d < 2*time.Hour-time.Minute {
		t.Errorf("new session lasts %v", d)
	}
	if res := e.loggedIn("viewer", "viewer-password").do(http.MethodPut, "/api/v1/settings/general",
		gen.GeneralSettingsInput{SessionLifetimeMinutes: 60, IdleTimeoutMinutes: 10}); res.Code != http.StatusForbidden {
		t.Errorf("viewer: %d", res.Code)
	}

	// After a restart the saved values apply again.
	sessions := auth.NewSessions(e.st, nil, auth.SessionOptions{})
	again := &loginsettings.Service{Store: e.st, Audit: e.srv.Audit, Secrets: testSecrets{}, Sessions: sessions}
	if err := again.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l, i := sessions.Lifetimes(); l != 2*time.Hour || i != 30*time.Minute {
		t.Errorf("after a restart: %v and %v", l, i)
	}
	if !strings.Contains(strings.Join(e.auditActions(), ","), "settings_update") {
		t.Errorf("no settings_update row: %v", e.auditActions())
	}
}

func TestAuditRetentionSetting(t *testing.T) {
	var svc *loginsettings.Service
	pokes := 0
	e := newTestEnv(t, func(o *Options) {
		svc = &loginsettings.Service{
			Store: o.Store, Audit: o.Audit, Secrets: testSecrets{}, Sessions: o.Sessions,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), RetentionChanged: func() { pokes++ },
		}
		if err := svc.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		o.LoginSettings = svc
	})
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	if g := decode[gen.GeneralSettings](t, c.do(http.MethodGet, "/api/v1/settings/general", nil)); g.AuditRetentionDays != 365 {
		t.Errorf("default retention %d", g.AuditRetentionDays)
	}
	for _, days := range []int{0, 29, 3651} {
		res := c.do(http.MethodPut, "/api/v1/settings/general",
			gen.GeneralSettingsInput{SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, AuditRetentionDays: ptr(days)})
		if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "audit_retention_days") {
			t.Errorf("%d days: %d %s", days, res.Code, res.Body)
		}
	}
	res := c.do(http.MethodPut, "/api/v1/settings/general",
		gen.GeneralSettingsInput{SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, AuditRetentionDays: ptr(90)})
	mustStatus(t, res, http.StatusOK)
	if g := decode[gen.GeneralSettings](t, res); g.AuditRetentionDays != 90 || svc.AuditRetentionDays() != 90 || pokes != 1 {
		t.Errorf("saved: %+v, service %d, %d pokes", g, svc.AuditRetentionDays(), pokes)
	}
	rows := e.auditRows()
	if last := rows[len(rows)-1]; last.Action != "settings_update" || !strings.Contains(last.Detail, `"audit_retention_days"`) {
		t.Errorf("audit row: %+v", last)
	}

	// Leaving it out keeps it, and changing only the lifetime doesn't prune again.
	res = c.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{SessionLifetimeMinutes: 240, IdleTimeoutMinutes: 60})
	mustStatus(t, res, http.StatusOK)
	if g := decode[gen.GeneralSettings](t, res); g.AuditRetentionDays != 90 || g.SessionLifetimeMinutes != 240 || pokes != 1 {
		t.Errorf("without retention: %+v, %d pokes", g, pokes)
	}

	// It survives a restart; a row saved before the setting existed loads as the default.
	again := &loginsettings.Service{Store: e.st, Audit: e.srv.Audit, Secrets: testSecrets{}}
	if err := again.Load(context.Background()); err != nil || again.AuditRetentionDays() != 90 {
		t.Errorf("after a restart: %d, %v", again.AuditRetentionDays(), err)
	}
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		return q.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: loginsettings.GeneralKey, Value: `{"session_lifetime_minutes":480,"idle_timeout_minutes":60}`, UpdatedAt: 1, UpdatedBy: "admin",
		})
	}); err != nil {
		t.Fatal(err)
	}
	old := &loginsettings.Service{Store: e.st, Audit: e.srv.Audit, Secrets: testSecrets{}}
	if err := old.Load(context.Background()); err != nil || old.AuditRetentionDays() != 365 {
		t.Errorf("an older row: %d, %v", old.AuditRetentionDays(), err)
	}
}
