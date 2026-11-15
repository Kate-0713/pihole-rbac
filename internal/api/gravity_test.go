// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// waitRun polls a run through path (a target's /gravity) until it is done, and returns it.
func waitRun(t *testing.T, c *client, path, id string) gen.GravityRun {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := c.do(http.MethodGet, path+"/"+id, nil)
		mustStatus(t, res, http.StatusOK)
		run := decode[gen.GravityRun](t, res)
		if run.Status == "done" {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("run %s still %s", id, run.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func gravityOutcomes(run gen.GravityRun) []string {
	var out []string
	for _, r := range run.Results {
		s := r.Instance + ":" + string(r.Status)
		if r.Reason != nil {
			s += ":" + string(*r.Reason)
		}
		if r.Error != nil {
			s += ":" + r.Error.Code
		}
		out = append(out, s)
	}
	return out
}

func TestGravityRun(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddList(piholetest.List{Address: adsList, Type: "block", Enabled: true})
	te.ph.SetGravity(piholetest.GravityRun{Lines: []string{"  [i] Neutrino emissions detected...", "  [✓] Done."}})
	path := te.path("/gravity")
	before := len(te.auditRows())

	if res := te.admin.do(http.MethodGet, path, nil); res.Code != http.StatusNotFound {
		t.Errorf("latest before any run: %d %s", res.Code, res.Body)
	}
	res := te.admin.do(http.MethodPost, path, nil)
	mustStatus(t, res, http.StatusAccepted)
	started := decode[gen.GravityRun](t, res)
	if started.Target != "i-"+strconv.FormatInt(te.id, 10) || started.StartedBy != "admin" || len(started.Results) != 1 {
		t.Errorf("started %+v", started)
	}
	run := waitRun(t, te.admin, path, started.Id)
	if got := gravityOutcomes(run); !slices.Equal(got, []string{"pihole1:ok"}) {
		t.Fatalf("results %v", got)
	}
	r := run.Results[0]
	if r.Domains == nil || *r.Domains != 1000 || r.LastUpdate == nil || r.DurationMs == nil || r.ListsFailed == nil || *r.ListsFailed != 0 {
		t.Errorf("result %+v", r)
	}
	if run.FinishedAt == nil || run.OutputLastSeq != 2 || len(run.Output) != 2 || run.Output[1].Text != "  [✓] Done." {
		t.Errorf("run %+v", run)
	}
	// Only the newer lines after a seq; the latest is this run.
	latest := decode[gen.GravityRun](t, te.admin.do(http.MethodGet, path+"?after=1", nil))
	if latest.Id != run.Id || len(latest.Output) != 1 || latest.Output[0].Seq != 2 {
		t.Errorf("latest after 1: %+v", latest.Output)
	}

	rows := te.auditRows()[before:]
	details := auditDetails(t, rows)
	var actions []string
	for _, row := range rows {
		actions = append(actions, row.Action)
		if strings.Contains(row.Detail, "Neutrino") {
			t.Error("output in an audit row")
		}
	}
	if !slices.Equal(actions, []string{audit.ActionGravityStart, audit.ActionGravityRun}) {
		t.Fatalf("audit %v", actions)
	}
	if details[0]["run_id"] != run.Id || details[1]["run_id"] != run.Id || details[1]["outcome"] != "ok" || details[1]["domains"] != float64(1000) {
		t.Errorf("audit details %v", details)
	}
	if rows[1].Username != "admin" {
		t.Errorf("gravity_run by %q", rows[1].Username)
	}

	t.Run("a failure", func(t *testing.T) {
		te.ph.SetGravity(piholetest.GravityRun{Fail: true})
		run := waitRun(t, te.admin, path, decode[gen.GravityRun](t, te.admin.do(http.MethodPost, path, nil)).Id)
		if got := gravityOutcomes(run); !slices.Equal(got, []string{"pihole1:failed:gravity_failed"}) {
			t.Errorf("results %v", got)
		}
		if !strings.Contains(run.Results[0].Error.Message, "Gravity failed") {
			t.Errorf("message %q", run.Results[0].Error.Message)
		}
		_, detail := te.lastAudit()
		if detail["outcome"] != "failed" || detail["error_code"] != "gravity_failed" {
			t.Errorf("audit %v", detail)
		}
	})

	t.Run("runs and ids", func(t *testing.T) {
		if res := te.admin.do(http.MethodGet, path+"/zz", nil); res.Code != http.StatusBadRequest {
			t.Errorf("a malformed id: %d", res.Code)
		}
		if res := te.admin.do(http.MethodGet, path+"/"+strings.Repeat("0", 24), nil); res.Code != http.StatusNotFound {
			t.Errorf("an unknown id: %d", res.Code)
		}
		if res := te.admin.do(http.MethodGet, path+"?after=-1", nil); res.Code != http.StatusBadRequest {
			t.Errorf("after=-1: %d", res.Code)
		}
	})
}

// TestGravityPermissions: starting a run needs gravity.run, watching it lists.view; neither gives the other.
func TestGravityPermissions(t *testing.T) {
	te := newTargetEnv(t)
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.ListsView, "instance", te.id))
	te.addGrantUser("runner", "runner-password-1", grant(rbac.GravityRun, "instance", te.id))
	viewer := te.loggedIn("viewer", "viewer-password-1")
	runner := te.loggedIn("runner", "runner-password-1")
	path := te.path("/gravity")

	if res := viewer.do(http.MethodPost, path, nil); res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != "gravity.run" {
		t.Errorf("viewer starting: %d %s", res.Code, res.Body)
	}
	res := runner.do(http.MethodPost, path, nil)
	mustStatus(t, res, http.StatusAccepted)
	id := decode[gen.GravityRun](t, res).Id
	if res := runner.do(http.MethodGet, path+"/"+id, nil); res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != "lists.view" {
		t.Errorf("runner watching: %d %s", res.Code, res.Body)
	}
	run := waitRun(t, viewer, path, id)
	if run.StartedBy != "runner" {
		t.Errorf("started by %q", run.StartedBy)
	}
	if rows := te.auditRows(); len(rows) < 2 || rows[len(rows)-1].Username != "runner" {
		t.Error("the run's audit rows aren't the runner's")
	}
}

// TestGroupGravity: through a mirrored group, members run one at a time, the primary first, and a failure stops the
// run; a run is refused while any instance it covers is in another, whether started through the group or the
// instance.
func TestGroupGravity(t *testing.T) {
	ge := newGroupEnv(t)
	for _, ph := range ge.ph {
		ph.AddList(piholetest.List{Address: adsList, Type: "block", Enabled: true})
	}
	path := ge.path("/gravity")
	before := len(ge.auditRows())
	ge.ph["beta"].SetGravity(piholetest.GravityRun{Fail: true})
	run := waitRun(t, ge.admin, path, decode[gen.GravityRun](t, ge.admin.do(http.MethodPost, path, nil)).Id)
	want := []string{"alpha:ok", "beta:failed:gravity_failed", "gamma:skipped:stopped"}
	if got := gravityOutcomes(run); !slices.Equal(got, want) {
		t.Errorf("results %v, want %v", got, want)
	}
	if !run.Results[0].Primary || ge.ph["gamma"].GravityRuns() != 0 {
		t.Error("gamma ran, or alpha isn't the primary")
	}
	rows, details := ge.auditSince(before)
	var got []string
	for i, row := range rows {
		got = append(got, row.Action+":"+row.InstanceName+":"+details[i]["via"].(string))
	}
	g := "g-" + strconv.FormatInt(ge.groupID, 10)
	if want := []string{"gravity_start:alpha:" + g, "gravity_run:alpha:" + g, "gravity_run:beta:" + g}; !slices.Equal(got, want) {
		t.Errorf("audit %v, want %v", got, want)
	}
	var names []string
	_ = json.Unmarshal([]byte(mustJSON(t, details[0]["instances"])), &names)
	if !slices.Equal(names, []string{"alpha", "beta", "gamma"}) {
		t.Errorf("gravity_start instances %v", names)
	}

	t.Run("one run at a time per instance", func(t *testing.T) {
		hold := make(chan struct{})
		ge.ph["beta"].SetGravity(piholetest.GravityRun{Hold: hold})
		id := decode[gen.GravityRun](t, ge.admin.do(http.MethodPost, path, nil)).Id
		defer func() { close(hold); waitRun(t, ge.admin, path, id) }()
		res := ge.admin.do(http.MethodPost, path, nil)
		if res.Code != http.StatusConflict || res.errorCode() != "conflict" {
			t.Fatalf("the group again: %d %s", res.Code, res.Body)
		}
		if busy, _ := errorDetails(t, res)["instances"].([]any); len(busy) == 0 {
			t.Errorf("details %v", errorDetails(t, res))
		}
		deadline := time.Now().Add(5 * time.Second)
		for ge.ph["beta"].GravityRuns() == 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		res = ge.admin.do(http.MethodPost, "/api/v1/targets/i-"+strconv.FormatInt(ge.ids["beta"], 10)+"/gravity", nil)
		if res.Code != http.StatusConflict {
			t.Errorf("beta on its own: %d %s", res.Code, res.Body)
		}
	})
}

func auditDetails(t *testing.T, rows []db.AuditLog) []map[string]any {
	t.Helper()
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		if err := json.Unmarshal([]byte(r.Detail), &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
