// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/clientoverrides"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// overrideClock is the clock a temporary change test moves.
type overrideClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *overrideClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *overrideClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// withOverrides gives the server a temporary client change service. It must come after withInstances.
func withOverrides(c *overrideClock) func(*Options) {
	return func(o *Options) {
		svc := &clientoverrides.Service{Store: o.Store, Audit: o.Audit, Instances: o.Instances,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now}
		if o.LoginSettings != nil {
			svc.Limits = o.LoginSettings.ClientOverrideLimits
		}
		o.ClientOverrides = svc
	}
}

// overrideEnv is the group env with a client 10.0.0.5 on every member, in Default and kids, and the Pi-hole groups
// kids and open on each.
func newOverrideEnv(t *testing.T) (*groupEnv, *overrideClock) {
	t.Helper()
	clock := &overrideClock{t: time.Now().Truncate(time.Second)}
	ge := newGroupEnv(t, withOverrides(clock))
	for _, ph := range ge.ph {
		kids := ph.AddGroup("kids")
		ph.AddGroup("open")
		ph.AddClient(piholetest.Client{Client: "10.0.0.5", Comment: "tablet", Groups: []int{0, kids}})
	}
	return ge, clock
}

// groupsOf is the client's groups on a member, by name, sorted.
func (ge *groupEnv) groupsOf(name string) []string {
	ge.t.Helper()
	var out []string
	for _, c := range ge.ph[name].Clients() {
		if c.Client != "10.0.0.5" {
			continue
		}
		for _, id := range c.Groups {
			for _, g := range ge.ph[name].Groups() {
				if g.ID == id {
					out = append(out, g.Name)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func (ge *groupEnv) wantGroups(what string, want ...string) {
	ge.t.Helper()
	for n := range ge.ph {
		if got := ge.groupsOf(n); !slices.Equal(got, want) {
			ge.t.Errorf("%s: %s has %v, want %v", what, n, got, want)
		}
	}
}

func tempPath(ge *groupEnv, id int64, suffix string) string {
	return ge.path("/clients/temporary/" + strconv.FormatInt(id, 10) + suffix)
}

func startBody(minutes int, reason string, groups ...string) gen.TemporaryClientStart {
	return gen.TemporaryClientStart{Client: "10.0.0.5", Groups: groups, DurationMinutes: &minutes, Reason: &reason}
}

func TestTemporaryChangeThroughAGroup(t *testing.T) {
	ge, clock := newOverrideEnv(t)
	before := ge.auditCount()

	res := ge.admin.do(http.MethodPost, ge.path("/clients/temporary"), startBody(60, "lab session", "Default", "open"))
	mustStatus(t, res, http.StatusOK)
	started := decode[gen.TemporaryClientWriteResults](t, res)
	if len(started.Results) != 3 || started.Change == nil || len(started.Change.Members) != 3 || started.Change.Status != "active" ||
		started.Change.Target != ge.target || started.Change.Reason != "lab session" || started.Change.CreatedBy != "admin" ||
		!started.Change.EndsAt.Equal(clock.now().Add(time.Hour)) {
		t.Fatalf("started %+v", started)
	}
	for _, r := range started.Results {
		if r.Status != "ok" || r.Groups == nil || !slices.Equal(*r.Groups, []string{"Default", "open"}) {
			t.Errorf("result %+v", r)
		}
	}
	ge.wantGroups("during", "Default", "open")
	rows, details := ge.auditSince(before)
	if len(rows) != 3 || rows[0].Action != audit.ActionClientTempSet || details[0]["override_id"] != float64(started.Change.Id) ||
		details[0]["via"] != ge.target || details[0]["reason"] != "lab session" {
		t.Errorf("audit rows %v %v", rows, details)
	}

	// Listed on the group, and on a member read-only with via.
	list := decode[gen.TemporaryClientChangeList](t, ge.admin.do(http.MethodGet, ge.path("/clients/temporary"), nil))
	if len(list.Changes) != 1 || list.MaxMinutes != clientoverrides.DefaultMinutes || !list.ReasonRequired {
		t.Errorf("group list %+v", list)
	}
	list = decode[gen.TemporaryClientChangeList](t, ge.admin.do(http.MethodGet, ge.instPath("beta", "/clients/temporary"), nil))
	if len(list.Changes) != 1 || list.Changes[0].Via == nil || *list.Changes[0].Via != ge.target {
		t.Errorf("member list %+v", list)
	}

	// Another change for the client on a member, or on the group again, is refused naming the first.
	for name, path := range map[string]string{"member": ge.instPath("gamma", "/clients/temporary"), "group": ge.path("/clients/temporary")} {
		res = ge.admin.do(http.MethodPost, path, startBody(30, "again", "Default"))
		if res.Code != http.StatusConflict || errorDetails(t, res)["override_id"] != float64(started.Change.Id) {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	// It is in the way of deleting what it covers.
	if res := ge.admin.do(http.MethodDelete, "/api/v1/instance-groups/"+strconv.FormatInt(ge.groupID, 10), nil); res.Code != http.StatusConflict {
		t.Errorf("deleting the group: %d %s", res.Code, res.Body)
	}
	if res := ge.admin.do(http.MethodDelete, instancePath(ge.ids["beta"], ""), nil); res.Code != http.StatusConflict {
		t.Errorf("deleting a member: %d %s", res.Code, res.Body)
	}

	// Extend it, and the change is audited with both ends.
	clock.advance(10 * time.Minute)
	later := clock.now().Add(2 * time.Hour)
	res = ge.admin.do(http.MethodPatch, tempPath(ge, started.Change.Id, ""), gen.TemporaryClientUpdate{EndsAt: later})
	mustStatus(t, res, http.StatusOK)
	if c := decode[gen.TemporaryClientChange](t, res); !c.EndsAt.Equal(later) {
		t.Errorf("extended %+v", c)
	}
	row, detail := ge.lastAuditRow()
	if row.Action != audit.ActionClientTempUpdate || detail["ends_at_after"] == nil || detail["ends_at_before"] == nil {
		t.Errorf("update audit %s %v", row.Action, detail)
	}
	res = ge.admin.do(http.MethodPatch, tempPath(ge, started.Change.Id, ""), gen.TemporaryClientUpdate{EndsAt: clock.now().Add(-time.Minute)})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "ends_at" {
		t.Errorf("an end in the past: %d %s", res.Code, res.Body)
	}

	// End now: every member goes back before the answer.
	before = ge.auditCount()
	res = ge.admin.do(http.MethodPost, tempPath(ge, started.Change.Id, "/end"), nil)
	mustStatus(t, res, http.StatusOK)
	ended := decode[gen.TemporaryClientWriteResults](t, res)
	if len(ended.Results) != 3 || ended.Change == nil || ended.Change.Status != "ended" || ended.Change.EndedBy == nil || *ended.Change.EndedBy != "admin" {
		t.Fatalf("ended %+v", ended)
	}
	for _, r := range ended.Results {
		if r.Status != "ok" || r.Groups == nil || !slices.Equal(*r.Groups, []string{"Default", "kids"}) {
			t.Errorf("end result %+v", r)
		}
	}
	ge.wantGroups("after", "Default", "kids")
	rows, _ = ge.auditSince(before)
	if len(rows) != 3 || rows[0].Action != audit.ActionClientTempEnd {
		t.Errorf("end audit %v", rows)
	}
	if res := ge.admin.do(http.MethodPost, tempPath(ge, started.Change.Id, "/end"), nil); res.Code != http.StatusConflict {
		t.Errorf("ending twice: %d", res.Code)
	}
	if res := ge.admin.do(http.MethodPost, tempPath(ge, started.Change.Id, "/retry"), nil); res.Code != http.StatusConflict {
		t.Errorf("retrying a change that didn't fail: %d", res.Code)
	}
	// Nothing blocks the delete now.
	if res := ge.admin.do(http.MethodDelete, "/api/v1/instance-groups/"+strconv.FormatInt(ge.groupID, 10), nil); res.Code != http.StatusNoContent {
		t.Errorf("deleting the group after: %d %s", res.Code, res.Body)
	}
}

func TestTemporaryChangeValidation(t *testing.T) {
	ge, _ := newOverrideEnv(t)
	for _, tc := range []struct {
		name  string
		body  gen.TemporaryClientStart
		field string
	}{
		{"no reason", startBody(60, "", "Default"), "reason"},
		{"too short", startBody(2, "x", "Default"), "duration_minutes"},
		{"too long", startBody(clientoverrides.DefaultMinutes+1, "x", "Default"), "duration_minutes"},
		{"already in those groups", startBody(60, "x", "Default", "kids"), "groups"},
		{"no client", gen.TemporaryClientStart{Groups: []string{"Default"}, DurationMinutes: ptr(60), Reason: ptr("x")}, "client"},
		{"neither duration nor end", gen.TemporaryClientStart{Client: "10.0.0.5", Groups: []string{"Default"}, Reason: ptr("x")}, "duration_minutes"},
	} {
		before := ge.auditCount()
		res := ge.admin.do(http.MethodPost, ge.path("/clients/temporary"), tc.body)
		if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != tc.field {
			t.Errorf("%s: %d %s", tc.name, res.Code, res.Body)
		}
		if ge.auditCount() != before || len(ge.piholeWritesAll()) != 0 {
			t.Errorf("%s: something was written", tc.name)
		}
	}
	// A client the primary doesn't have is a 404.
	body := startBody(60, "x", "Default")
	body.Client = "10.9.9.9"
	if res := ge.admin.do(http.MethodPost, ge.path("/clients/temporary"), body); res.Code != http.StatusNotFound {
		t.Errorf("an unknown client: %d %s", res.Code, res.Body)
	}
}

func (ge *groupEnv) piholeWritesAll() []string {
	var out []string
	for _, ph := range ge.ph {
		for _, r := range ph.Requests() {
			if len(r) > 3 && r[:4] != "GET " {
				out = append(out, r)
			}
		}
	}
	// Logging in is a POST.
	return slices.DeleteFunc(out, func(r string) bool { return r == "POST /api/auth" || r == "DELETE /api/auth" })
}

// A member without a Pi-hole group of that name fails on its own and isn't stored; the others take the change, and
// ending it only touches those.
func TestTemporaryChangeMemberMissingAGroup(t *testing.T) {
	ge, _ := newOverrideEnv(t)
	ge.ph["alpha"].AddGroup("special")
	ge.ph["gamma"].AddGroup("special")
	res := ge.admin.do(http.MethodPost, ge.path("/clients/temporary"), startBody(60, "x", "Default", "special"))
	mustStatus(t, res, http.StatusMultiStatus)
	out := decode[gen.TemporaryClientWriteResults](t, res)
	var failed []string
	for _, r := range out.Results {
		if r.Status != "ok" {
			failed = append(failed, r.Instance)
			if r.Error == nil || r.Error.Code != "pihole_group_missing" {
				t.Errorf("error %+v", r.Error)
			}
		}
	}
	if !slices.Equal(failed, []string{"beta"}) || out.Change == nil || len(out.Change.Members) != 2 {
		t.Fatalf("results %+v", out)
	}
	if got := ge.groupsOf("beta"); !slices.Equal(got, []string{"Default", "kids"}) {
		t.Errorf("beta was changed: %v", got)
	}
	res = ge.admin.do(http.MethodPost, tempPath(ge, out.Change.Id, "/end"), nil)
	mustStatus(t, res, http.StatusOK)
	if end := decode[gen.TemporaryClientWriteResults](t, res); len(end.Results) != 2 {
		t.Errorf("only the stored members are put back: %+v", end.Results)
	}
	ge.wantGroups("after", "Default", "kids")
}

// A member that is down at the end stays pending, shown as reverting, and the scheduler pass puts it back.
func TestTemporaryChangeEndWithAMemberDown(t *testing.T) {
	ge, clock := newOverrideEnv(t)
	res := ge.admin.do(http.MethodPost, ge.path("/clients/temporary"), startBody(60, "x", "Default", "open"))
	mustStatus(t, res, http.StatusOK)
	id := decode[gen.TemporaryClientWriteResults](t, res).Change.Id

	ge.unreachable("gamma")
	clock.advance(time.Minute)
	res = ge.admin.do(http.MethodPost, tempPath(ge, id, "/end"), nil)
	mustStatus(t, res, http.StatusMultiStatus)
	out := decode[gen.TemporaryClientWriteResults](t, res)
	if out.Change == nil || out.Change.Status != "active" || !out.Change.Overdue {
		t.Fatalf("a member failed: %+v", out.Change)
	}
	var pending []string
	for _, m := range out.Change.Members {
		if m.RevertStatus != "ok" {
			pending = append(pending, m.Instance)
		}
	}
	if !slices.Equal(pending, []string{"gamma"}) {
		t.Errorf("pending %v", pending)
	}
}

func TestTemporaryChangePermissions(t *testing.T) {
	ge, _ := newOverrideEnv(t)
	viewer := ge.userWith("viewer", rbac.ClientsView)
	editor := ge.userWith("editor", rbac.ClientsView, rbac.ClientsEdit)
	res := editor.do(http.MethodPost, ge.path("/clients/temporary"), startBody(60, "x", "Default", "open"))
	mustStatus(t, res, http.StatusOK)
	id := decode[gen.TemporaryClientWriteResults](t, res).Change.Id

	for name, tc := range map[string]struct {
		c      *client
		method string
		path   string
		body   any
		want   int
	}{
		"viewer reads":          {viewer, http.MethodGet, ge.path("/clients/temporary"), nil, http.StatusOK},
		"viewer can't start":    {viewer, http.MethodPost, ge.path("/clients/temporary"), startBody(60, "x", "Default"), http.StatusForbidden},
		"viewer can't extend":   {viewer, http.MethodPatch, tempPath(ge, id, ""), gen.TemporaryClientUpdate{EndsAt: time.Now().Add(time.Hour)}, http.StatusForbidden},
		"viewer can't end":      {viewer, http.MethodPost, tempPath(ge, id, "/end"), nil, http.StatusForbidden},
		"viewer can't retry":    {viewer, http.MethodPost, tempPath(ge, id, "/retry"), nil, http.StatusForbidden},
		"anyone with edit ends": {editor, http.MethodPost, tempPath(ge, id, "/end"), nil, http.StatusOK},
	} {
		if res := tc.c.do(tc.method, tc.path, tc.body); res.Code != tc.want {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	// Someone with nothing on the group can't read it, and an id from one target isn't found through another.
	if res := ge.admin.do(http.MethodPost, ge.instPath("gamma", "/clients/temporary"), startBody(60, "x", "Default", "open")); res.Code != http.StatusOK {
		t.Fatalf("on a member: %d %s", res.Code, res.Body)
	}
	if res := ge.admin.do(http.MethodPost, "/api/v1/targets/i-"+strconv.FormatInt(ge.ids["alpha"], 10)+"/clients/temporary/"+strconv.FormatInt(id, 10)+"/end", nil); res.Code != http.StatusNotFound {
		t.Errorf("an id through another target: %d %s", res.Code, res.Body)
	}
}

// The limits are the general settings, which the list also reports.
func TestTemporaryChangeSettings(t *testing.T) {
	clock := &overrideClock{t: time.Now().Truncate(time.Second)}
	te := newTargetEnv(t, withLoginSettings(t, nil), withOverrides(clock))
	kids := te.ph.AddGroup("kids")
	te.ph.AddGroup("open")
	te.ph.AddClient(piholetest.Client{Client: "10.0.0.5", Groups: []int{0, kids}})

	res := te.admin.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{
		SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, ClientTempMaxMinutes: ptr(120), ClientTempReasonRequired: ptr(false)})
	mustStatus(t, res, http.StatusOK)
	if g := decode[gen.GeneralSettings](t, res); g.ClientTempMaxMinutes != 120 || g.ClientTempReasonRequired {
		t.Errorf("settings %+v", g)
	}
	list := decode[gen.TemporaryClientChangeList](t, te.admin.do(http.MethodGet, te.path("/clients/temporary"), nil))
	if list.MaxMinutes != 120 || list.ReasonRequired {
		t.Errorf("list limits %+v", list)
	}
	minutes := 121
	res = te.admin.do(http.MethodPost, te.path("/clients/temporary"), gen.TemporaryClientStart{Client: "10.0.0.5", Groups: []string{"Default", "open"}, DurationMinutes: &minutes})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["max_minutes"] != float64(120) {
		t.Errorf("over the maximum: %d %s", res.Code, res.Body)
	}
	minutes = 120
	res = te.admin.do(http.MethodPost, te.path("/clients/temporary"), gen.TemporaryClientStart{Client: "10.0.0.5", Groups: []string{"Default", "open"}, DurationMinutes: &minutes})
	mustStatus(t, res, http.StatusOK)
	if out := decode[gen.TemporaryClientWriteResults](t, res); len(out.Results) != 1 || out.Change.Reason != "" {
		t.Errorf("an instance start without a reason %+v", out)
	}
	// Out of range settings are refused.
	res = te.admin.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{
		SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, ClientTempMaxMinutes: ptr(1)})
	if res.Code != http.StatusBadRequest {
		t.Errorf("a maximum of 1 minute: %d %s", res.Code, res.Body)
	}
}

// lastAuditRow returns the newest audit row of a group env, and its detail decoded.
func (ge *groupEnv) lastAuditRow() (db.AuditLog, map[string]any) {
	ge.t.Helper()
	rows, details := ge.auditSince(ge.auditCount() - 1)
	return rows[0], details[0]
}
