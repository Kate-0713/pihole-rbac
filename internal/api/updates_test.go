// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/updates"
)

type stubReleases struct {
	rel   release.Release
	err   error
	calls int
}

func (s *stubReleases) Latest(context.Context) (release.Release, error) {
	s.calls++
	return s.rel, s.err
}

type updatesEnv struct {
	*testEnv
	releases *stubReleases
	restarts int
	file     string
}

// newUpdatesEnv is a server running v2.0.0 with the given install kind, an admin and a user without app.update.
func newUpdatesEnv(t *testing.T, install updates.Install) *updatesEnv {
	t.Helper()
	ue := &updatesEnv{
		releases: &stubReleases{rel: release.Release{Version: mustVersion(t, "v2.1.0"), PublishedAt: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}},
		file:     filepath.Join(t.TempDir(), "update.request"),
	}
	ue.testEnv = newTestEnv(t, func(o *Options) {
		o.Updates = &updates.Service{
			Store: o.Store, Audit: o.Audit, Releases: ue.releases, Install: install, RequestFile: ue.file,
			Current: func() (release.Version, bool) { return mustVersion(t, "v2.0.0"), true },
			Logger:  o.Logger,
		}
		o.Restart = func() { ue.restarts++ }
	})
	ue.addUser("admin", "admin-password-1", true)
	ue.addRoleUser("reloader", "reloader-password-1", rbac.ConfigReload)
	return ue
}

func mustVersion(t *testing.T, s string) release.Version {
	t.Helper()
	v, err := release.ParseTag(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUpdateRoutesNeedAppUpdate(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallLXC)
	anon := ue.client("10.0.0.9:1")
	anon.fetchCSRF()
	reloader := ue.loggedIn("reloader", "reloader-password-1")

	tests := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/system/update"},
		{http.MethodPost, "/api/v1/system/update"},
		{http.MethodPost, "/api/v1/system/update/check"},
		{http.MethodPost, "/api/v1/system/restart"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var body any
			if tt.method == http.MethodPost {
				body = struct{}{}
			}
			if res := anon.do(tt.method, tt.path, body); res.Code != http.StatusUnauthorized {
				t.Errorf("anonymous: %d", res.Code)
			}
			before := len(ue.auditRows())
			res := reloader.do(tt.method, tt.path, body)
			if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "app.update") {
				t.Fatalf("without app.update: %d %s", res.Code, res.Body)
			}
			rows := ue.auditRows()[before:]
			if tt.method == http.MethodPost && (len(rows) != 1 || rows[0].Action != audit.ActionPermissionDenied) {
				t.Errorf("refused POST audit = %+v", rows)
			}
			if tt.method == http.MethodGet && len(rows) != 0 {
				t.Errorf("refused GET was audited")
			}
		})
	}
	if ue.restarts != 0 || ue.releases.calls != 0 {
		t.Errorf("a refused request did something: %d restarts, %d checks", ue.restarts, ue.releases.calls)
	}
	if _, err := os.Stat(ue.file); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused request touched the request file")
	}
}

func TestGetVersion(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallOther)
	ue.addRoleUser("reader", "reader-password-1", rbac.DomainsView) // nothing global
	if res := ue.client("10.0.0.9:1").do(http.MethodGet, "/api/v1/system/version", nil); res.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", res.Code)
	}
	res := ue.loggedIn("reader", "reader-password-1").do(http.MethodGet, "/api/v1/system/version", nil)
	mustStatus(t, res, http.StatusOK)
	v := decode[gen.VersionInfo](t, res)
	if v.Version != buildinfo.Version || v.Commit != buildinfo.Commit || v.BuildDate != buildinfo.Date || !v.Development {
		t.Errorf("version = %+v (a test binary is a development build)", v)
	}
}

func TestUpdateStatusAndCheck(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallLXC)
	admin := ue.loggedIn("admin", "admin-password-1")

	res := admin.do(http.MethodGet, "/api/v1/system/update", nil)
	mustStatus(t, res, http.StatusOK)
	st := decode[gen.UpdateStatus](t, res)
	if st.Install != gen.UpdateStatusInstall("lxc") || st.Development || !st.CheckEnabled || st.CheckedAt != nil ||
		st.Latest != nil || st.UpdateAvailable || !st.CanRequest || len(st.Requests) != 0 {
		t.Fatalf("before a check: %+v", st)
	}
	if ue.releases.calls != 0 {
		t.Fatal("reading the status asked GitHub")
	}

	before := len(ue.auditRows())
	res = admin.do(http.MethodPost, "/api/v1/system/update/check", nil)
	mustStatus(t, res, http.StatusOK)
	st = decode[gen.UpdateStatus](t, res)
	if st.Latest == nil || st.Latest.Version != "v2.1.0" || st.Latest.Url != "https://github.com/Kate-0713/pihole-rbac/releases/tag/v2.1.0" ||
		st.Latest.PublishedAt == nil || !st.UpdateAvailable || st.CheckedAt == nil || st.CheckError != nil {
		t.Fatalf("after a check: %+v", st)
	}
	if len(ue.auditRows()) != before {
		t.Error("a check was audited")
	}

	// Within a minute: answered from the stored result.
	ue.releases.err = errors.New("GitHub answered 502 Bad Gateway")
	mustStatus(t, admin.do(http.MethodPost, "/api/v1/system/update/check", nil), http.StatusOK)
	if ue.releases.calls != 1 {
		t.Errorf("GitHub asked %d times within a minute", ue.releases.calls)
	}
}

func TestCheckForUpdateOff(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallDocker)
	ue.srv.Updates.Releases = nil
	admin := ue.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodPost, "/api/v1/system/update/check", nil)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "PIHOLE_RBAC_UPDATE_CHECK") {
		t.Fatalf("check off: %d %s", res.Code, res.Body)
	}
	st := decode[gen.UpdateStatus](t, admin.do(http.MethodGet, "/api/v1/system/update", nil))
	if st.CheckEnabled || st.CanRequest || st.Install != "docker" {
		t.Errorf("status = %+v", st)
	}
}

func TestRequestUpdate(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallLXC)
	admin := ue.loggedIn("admin", "admin-password-1")
	path := "/api/v1/system/update"

	tests := []struct {
		name   string
		body   any
		status int
		code   string
		field  string
	}{
		{"not a version", map[string]any{"target_version": "latest"}, http.StatusBadRequest, "validation_failed", "target_version"},
		{"not newer", map[string]any{"target_version": "v2.0.0"}, http.StatusBadRequest, "validation_failed", "target_version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := admin.do(http.MethodPost, path, tt.body)
			if res.Code != tt.status || res.errorCode() != tt.code {
				t.Fatalf("%d %s", res.Code, res.Body)
			}
			if tt.field != "" && detailsField(t, res) != tt.field {
				t.Errorf("field = %q", detailsField(t, res))
			}
		})
	}

	res := admin.do(http.MethodPost, path, map[string]any{"target_version": " v2.0.1-rc.1 "})
	mustStatus(t, res, http.StatusAccepted)
	r := decode[gen.UpdateRequest](t, res)
	if r.Status != "pending" || r.TargetVersion == nil || *r.TargetVersion != "v2.0.1-rc.1" || r.RequestedBy != "admin" {
		t.Fatalf("request = %+v", r)
	}
	if b, err := os.ReadFile(ue.file); err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Fatalf("request file = %q, %v", b, err)
	}
	rows := ue.auditRows()
	last := rows[len(rows)-1]
	if last.Action != audit.ActionUpdateRequest || last.Username != "admin" || last.Ip == "" ||
		!strings.Contains(last.Detail, `"version":"v2.0.1-rc.1"`) {
		t.Errorf("audit = %+v", last)
	}

	st := decode[gen.UpdateStatus](t, admin.do(http.MethodGet, path, nil))
	if st.CanRequest || len(st.Requests) != 1 || st.Requests[0].Id != r.Id {
		t.Errorf("status while pending = %+v", st)
	}
	res = admin.do(http.MethodPost, path, map[string]any{})
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "already pending") {
		t.Fatalf("second request: %d %s", res.Code, res.Body)
	}
}

func TestRequestUpdateNotLXC(t *testing.T) {
	for _, tt := range []struct {
		install updates.Install
		want    string
	}{{updates.InstallDocker, "docker compose pull"}, {updates.InstallOther, "LXC install"}} {
		t.Run(string(tt.install), func(t *testing.T) {
			ue := newUpdatesEnv(t, tt.install)
			res := ue.loggedIn("admin", "admin-password-1").do(http.MethodPost, "/api/v1/system/update", map[string]any{})
			if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), tt.want) {
				t.Fatalf("%d %s", res.Code, res.Body)
			}
		})
	}
}

func TestRestartApp(t *testing.T) {
	ue := newUpdatesEnv(t, updates.InstallLXC)
	admin := ue.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodPost, "/api/v1/system/restart", nil)
	mustStatus(t, res, http.StatusAccepted)
	if ue.restarts != 1 {
		t.Fatalf("restarts = %d", ue.restarts)
	}
	rows := ue.auditRows()
	if last := rows[len(rows)-1]; last.Action != audit.ActionAppRestart || last.Username != "admin" {
		t.Errorf("audit = %+v", last)
	}
}
