// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// withClientReset gives the server a client reset service. It must come after withInstances.
func withClientReset(o *Options) {
	o.ClientReset = &clientreset.Service{
		Store: o.Store, Audit: o.Audit, Instances: o.Instances, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

type ruleIn = struct {
	CommentPrefix string               `json:"comment_prefix"`
	GroupMatch    gen.ClientResetMatch `json:"group_match"`
	Id            int64                `json:"id"`
	PiholeGroups  []string             `json:"pihole_groups"`
	Scope         gen.ClientResetScope `json:"scope"`
}

func rulesInput(rules ...ruleIn) gen.ClientResetRulesInput {
	return gen.ClientResetRulesInput{Rules: rules}
}

// resetEnv is the mirrored group "site" (alpha the primary, beta and gamma) with AUTOSET-lab on every member, and on
// each a client TEST-laptop in the Default group.
func newResetEnv(t *testing.T) *groupEnv {
	t.Helper()
	ge := newGroupEnv(t, withClientReset)
	for _, n := range []string{"alpha", "beta", "gamma"} {
		ge.ph[n].AddGroup("AUTOSET-lab")
		ge.ph[n].AddClient(piholetest.Client{Client: "10.0.0.1", Comment: "TEST-laptop"})
	}
	return ge
}

func clientGroups(ph *piholetest.Server, id string) []int {
	for _, c := range ph.Clients() {
		if c.Client == id {
			return c.Groups
		}
	}
	return nil
}

func groupID(ph *piholetest.Server, name string) int {
	for _, g := range ph.Groups() {
		if g.Name == name {
			return g.ID
		}
	}
	return -1
}

func TestClientResetRulesAPI(t *testing.T) {
	ge := newResetEnv(t)
	res := ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", rulesInput(
		ruleIn{Scope: "group", Id: ge.groupID, CommentPrefix: "TEST-", GroupMatch: "names", PiholeGroups: []string{"AUTOSET-lab"}},
		ruleIn{Scope: "instance", Id: ge.ids["alpha"], CommentPrefix: "NINJA-", GroupMatch: "prefixes", PiholeGroups: []string{"AUTO"}},
	))
	mustStatus(t, res, http.StatusOK)
	got := decode[gen.ClientResetRules](t, res)
	if len(got.Rules) != 2 || got.Rules[0].Name != "alpha" || got.Rules[1].Name != "site" || got.Rules[1].GroupMatch != "names" ||
		len(got.Instances) != 3 || len(got.Groups) != 1 {
		t.Fatalf("rules %+v", got)
	}
	again := decode[gen.ClientResetRules](t, ge.admin.do(http.MethodGet, "/api/v1/client-reset/rules", nil))
	if len(again.Rules) != 2 || again.Rules[0].CommentPrefix != "NINJA-" {
		t.Errorf("GET %+v", again)
	}
	if !slices.Contains(ge.auditActions(), audit.ActionClientResetRules) {
		t.Error("not audited")
	}

	for _, tc := range []struct {
		rule  ruleIn
		field string
	}{
		{ruleIn{Scope: "nope", Id: ge.ids["alpha"], CommentPrefix: "X", GroupMatch: "names", PiholeGroups: []string{"g"}}, "scope"},
		{ruleIn{Scope: "instance", Id: ge.ids["alpha"], CommentPrefix: "", GroupMatch: "names", PiholeGroups: []string{"g"}}, "comment_prefix"},
		{ruleIn{Scope: "instance", Id: ge.ids["alpha"], CommentPrefix: "X", GroupMatch: "regex", PiholeGroups: []string{"g"}}, "group_match"},
		{ruleIn{Scope: "instance", Id: ge.ids["alpha"], CommentPrefix: "X", GroupMatch: "names"}, "pihole_groups"},
		{ruleIn{Scope: "instance", Id: 999, CommentPrefix: "X", GroupMatch: "names", PiholeGroups: []string{"g"}}, "id"},
	} {
		res := ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", rulesInput(tc.rule))
		mustStatus(t, res, http.StatusBadRequest)
		if f := detailsField(t, res); f != tc.field {
			t.Errorf("%+v: field %q, want %q", tc.rule, f, tc.field)
		}
	}
	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", map[string]any{"rules": []any{}, "extra": 1}), http.StatusOK)

	// Without settings.manage, even with clientreset.run everywhere.
	ge.addRoleUser("rita", "rita-password-1", rbac.ClientResetRun)
	rita := ge.loggedIn("rita", "rita-password-1")
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/client-reset/rules"},
		{http.MethodPut, "/api/v1/client-reset/rules"},
		{http.MethodGet, "/api/v1/client-reset/runs"},
	} {
		var body any
		if r.method == http.MethodPut {
			body = rulesInput()
		}
		if res := rita.do(r.method, r.path, body); res.Code != http.StatusForbidden || res.errorCode() != "forbidden" {
			t.Errorf("%s %s: %d %s", r.method, r.path, res.Code, res.Body)
		}
	}
}

func detailsField(t *testing.T, res response) string {
	t.Helper()
	body := decode[gen.Error](t, res)
	if body.Error.Details == nil {
		return ""
	}
	f, _ := (*body.Error.Details)["field"].(string)
	return f
}

func TestClientResetRunAPI(t *testing.T) {
	ge := newResetEnv(t)
	// No rules yet: nothing to preview or run.
	if res := ge.admin.do(http.MethodPost, ge.path("/client-reset/run"), nil); res.Code != http.StatusConflict || res.errorCode() != "conflict" {
		t.Fatalf("run without rules: %d %s", res.Code, res.Body)
	}
	mustStatus(t, ge.admin.do(http.MethodGet, ge.path("/client-reset/preview"), nil), http.StatusConflict)
	empty := decode[gen.ClientResetRunList](t, ge.admin.do(http.MethodGet, ge.path("/client-reset/runs"), nil))
	if len(empty.Runs) != 0 || empty.Rules == nil || *empty.Rules != 0 {
		t.Errorf("runs before any %+v", empty)
	}

	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", rulesInput(
		ruleIn{Scope: "group", Id: ge.groupID, CommentPrefix: "TEST-", GroupMatch: "names", PiholeGroups: []string{"AUTOSET-lab"}},
	)), http.StatusOK)

	pv := decode[gen.ClientResetPreview](t, ge.admin.do(http.MethodGet, ge.path("/client-reset/preview"), nil))
	if pv.TargetName != "site" || pv.Rules != 1 || len(pv.Instances) != 3 || !pv.Instances[0].Primary ||
		len(pv.Instances[1].Reset) != 1 || pv.Instances[1].Reset[0].GroupsAfter[0] != "AUTOSET-lab" {
		t.Fatalf("preview %+v", pv)
	}
	if g := clientGroups(ge.ph["beta"], "10.0.0.1"); !slices.Equal(g, []int{0}) {
		t.Fatalf("the preview changed a client: %v", g)
	}

	// gamma is down: the run still answers 200, partial, with gamma's code.
	ge.down("gamma")
	before := len(ge.auditRows())
	res := ge.admin.do(http.MethodPost, ge.path("/client-reset/run"), nil)
	mustStatus(t, res, http.StatusOK)
	run := decode[gen.ClientResetRun](t, res)
	if run.Status != "partial" || run.Trigger != "manual" || run.Username != "admin" || run.Target != ge.target ||
		run.FinishedAt == nil || len(run.Instances) != 3 {
		t.Fatalf("run %+v", run)
	}
	if g := run.Instances[2]; g.Instance != "gamma" || g.Status != "failed" || g.Code == nil || *g.Code != "pihole_status_error" {
		t.Errorf("gamma %+v", g)
	}
	for _, n := range []string{"alpha", "beta"} {
		if g := clientGroups(ge.ph[n], "10.0.0.1"); !slices.Equal(g, []int{groupID(ge.ph[n], "AUTOSET-lab")}) {
			t.Errorf("%s: client groups %v", n, g)
		}
	}
	rows, details := ge.auditSince(before)
	if len(rows) != 3 {
		t.Fatalf("%d audit rows, want one per member", len(rows))
	}
	for i, r := range rows {
		if r.Action != audit.ActionClientReset || r.Target != ge.target || details[i]["via"] != ge.target {
			t.Errorf("row %+v %v", r, details[i])
		}
	}

	// Two more runs, then the history, newest first and paged.
	ge.ph["gamma"].Handle(func(http.ResponseWriter, *http.Request) bool { return false })
	for range 2 {
		mustStatus(t, ge.admin.do(http.MethodPost, ge.path("/client-reset/run"), nil), http.StatusOK)
	}
	list := decode[gen.ClientResetRunList](t, ge.admin.do(http.MethodGet, ge.path("/client-reset/runs"), nil))
	if len(list.Runs) != 3 || list.Runs[0].Id < list.Runs[1].Id || list.Rules == nil || *list.Rules != 1 || list.NextCursor != nil {
		t.Fatalf("runs %+v", list)
	}
	if list.Runs[1].Status != "ok" || list.Runs[1].Instances[2].Status != "ok" || len(list.Runs[1].Instances[2].Reset) != 1 {
		t.Errorf("the run after gamma came back %+v", list.Runs[1])
	}
	page := decode[gen.ClientResetRunList](t, ge.admin.do(http.MethodGet, ge.path("/client-reset/runs?limit=2"), nil))
	if len(page.Runs) != 2 || page.NextCursor == nil {
		t.Fatalf("page 1 %+v", page)
	}
	next := decode[gen.ClientResetRunList](t, ge.admin.do(http.MethodGet, ge.path("/client-reset/runs?limit=2&cursor="+*page.NextCursor), nil))
	if len(next.Runs) != 1 || next.Runs[0].Id != list.Runs[2].Id || next.NextCursor != nil {
		t.Errorf("page 2 %+v", next)
	}
	all := decode[gen.ClientResetRunList](t, ge.admin.do(http.MethodGet, "/api/v1/client-reset/runs", nil))
	if len(all.Runs) != 3 || all.Rules != nil {
		t.Errorf("every run %+v", all)
	}
	for _, q := range []string{"?limit=0", "?limit=201", "?cursor=nope", "?cursor=" + encodeAuditCursor(5)} {
		if res := ge.admin.do(http.MethodGet, "/api/v1/client-reset/runs"+q, nil); res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, res.Code)
		}
	}

	// A disabled instance is a 404; another instance without rules is a 409.
	mustStatus(t, ge.admin.do(http.MethodPost, instancePath(ge.ids["gamma"], "/disable"), nil), http.StatusOK)
	if res := ge.admin.do(http.MethodPost, ge.instPath("gamma", "/client-reset/run"), nil); res.Code != http.StatusNotFound {
		t.Errorf("disabled instance: %d %s", res.Code, res.Body)
	}
	if res := ge.admin.do(http.MethodPost, ge.instPath("beta", "/client-reset/run"), nil); res.Code != http.StatusConflict {
		t.Errorf("instance without rules: %d %s", res.Code, res.Body)
	}
}

func TestClientResetPermissions(t *testing.T) {
	ge := newResetEnv(t)
	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", rulesInput(
		ruleIn{Scope: "group", Id: ge.groupID, CommentPrefix: "TEST-", GroupMatch: "names", PiholeGroups: []string{"AUTOSET-lab"}},
		ruleIn{Scope: "instance", Id: ge.ids["alpha"], CommentPrefix: "TEST-", GroupMatch: "names", PiholeGroups: []string{"AUTOSET-lab"}},
	)), http.StatusOK)
	grant := func(scope string, id int64) db.InsertGrantParams {
		g := db.InsertGrantParams{Permission: string(rbac.ClientResetRun), ScopeType: scope}
		if scope == "instance" {
			g.InstanceID = sql.NullInt64{Int64: id, Valid: true}
		} else {
			g.GroupID = sql.NullInt64{Int64: id, Valid: true}
		}
		return g
	}
	ge.addGrantUser("ivy", "ivy-password-12", grant("instance", ge.ids["alpha"]))
	ge.addGrantUser("gus", "gus-password-12", grant("group", ge.groupID))
	ge.addGrantUser("vic", "vic-password-12", db.InsertGrantParams{Permission: string(rbac.ClientsEdit), ScopeType: "all"})
	ivy, gus, vic := ge.loggedIn("ivy", "ivy-password-12"), ge.loggedIn("gus", "gus-password-12"), ge.loggedIn("vic", "vic-password-12")
	alpha := "/api/v1/targets/i-" + strconv.FormatInt(ge.ids["alpha"], 10)

	for _, tc := range []struct {
		who    string
		c      *client
		path   string
		status int
	}{
		{"ivy on alpha", ivy, alpha, http.StatusOK},
		{"ivy on the group", ivy, ge.path(""), http.StatusForbidden},
		// A grant on a mirrored group covers the group, not one member alone.
		{"gus on the group", gus, ge.path(""), http.StatusOK},
		{"gus on alpha", gus, alpha, http.StatusForbidden},
		{"clients.edit isn't enough", vic, ge.path(""), http.StatusForbidden},
		{"a target that doesn't exist", ivy, "/api/v1/targets/i-999", http.StatusForbidden},
	} {
		for _, op := range []struct{ method, suffix string }{
			{http.MethodGet, "/client-reset/preview"},
			{http.MethodGet, "/client-reset/runs"},
			{http.MethodPost, "/client-reset/run"},
		} {
			if res := tc.c.do(op.method, tc.path+op.suffix, nil); res.Code != tc.status {
				t.Errorf("%s: %s %s = %d %s, want %d", tc.who, op.method, op.suffix, res.Code, res.Body, tc.status)
			}
		}
	}
	// The refused runs are audited; the refused reads aren't.
	var denied int
	for _, r := range ge.auditRows() {
		if r.Action == audit.ActionPermissionDenied {
			denied++
			if !strings.Contains(r.Detail, "client-reset/run") {
				t.Errorf("denied row %s", r.Detail)
			}
		}
	}
	if denied != 4 {
		t.Errorf("%d permission_denied rows, want 4 (one per refused run)", denied)
	}
	if res := ivy.do(http.MethodGet, "/api/v1/targets/x-1/client-reset/runs", nil); res.Code != http.StatusBadRequest {
		t.Errorf("bad target: %d", res.Code)
	}
}

// A run can take longer than the server's write timeout; its route gets a longer write deadline, so the answer still
// arrives. Checked on a real server whose write timeout is shorter than a slow Pi-hole makes the run.
func TestClientResetOutlivesWriteTimeout(t *testing.T) {
	ge := newResetEnv(t)
	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/client-reset/rules", rulesInput(
		ruleIn{Scope: "group", Id: ge.groupID, CommentPrefix: "TEST-", GroupMatch: "names", PiholeGroups: []string{"AUTOSET-lab"}},
	)), http.StatusOK)
	ge.ph["beta"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut {
			time.Sleep(400 * time.Millisecond)
		}
		return false
	})
	srv := httptest.NewUnstartedServer(ge.h)
	srv.Config.WriteTimeout = 150 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	send := func(path string) (*http.Response, error) {
		req := ge.admin.request(http.MethodPost, path, nil)
		req.RequestURI = ""
		u, _ := url.Parse(srv.URL + path)
		req.URL, req.Host = u, "example.com" // the Origin the test client sends
		return srv.Client().Do(req)
	}
	res, err := send(ge.path("/client-reset/run"))
	if err != nil {
		t.Fatalf("the run's answer didn't arrive: %v", err)
	}
	defer res.Body.Close()
	var run gen.ClientResetRun
	if err := json.NewDecoder(res.Body).Decode(&run); err != nil || res.StatusCode != http.StatusOK || run.Status != "ok" {
		t.Fatalf("run %d %+v %v", res.StatusCode, run, err)
	}
}
