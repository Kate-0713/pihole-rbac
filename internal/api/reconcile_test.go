// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func (ge *groupEnv) reconcilePath() string {
	return "/api/v1/instance-groups/" + strconv.FormatInt(ge.groupID, 10) + "/reconcile"
}

// differ gives alpha (the primary) a kids group, two entries and a client, and beta an entry of its own.
func (ge *groupEnv) differ() {
	kids := ge.ph["alpha"].AddGroup("kids")
	ge.ph["alpha"].AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Groups: []int{kids}, Enabled: true})
	ge.ph["alpha"].AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Enabled: true})
	ge.ph["alpha"].AddClient(piholetest.Client{Client: "10.0.1.5", Groups: []int{kids}})
	ge.ph["beta"].AddDomain(piholetest.Domain{Domain: "beta-only.example", Type: "deny", Kind: "exact", Enabled: true})
}

func TestReconcileAllAPI(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	ge.differ()
	before := ge.auditCount()

	res := ge.admin.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{All: ptr(true)})
	mustStatus(t, res, http.StatusOK)
	out := decode[gen.ReconcileResult](t, res)
	if out.Report.State != "checked" || out.Report.Drifted {
		t.Errorf("report after reconcile %+v", out.Report)
	}
	if len(out.Members) != 2 || out.Members[0].Instance != "beta" {
		t.Errorf("members %+v", out.Members)
	}
	var beta []string
	for _, r := range out.Results {
		if r.Status != "ok" {
			t.Errorf("failed %+v", r)
		}
		if r.Instance == "beta" {
			beta = append(beta, string(r.Item)+":"+string(r.Action))
		}
	}
	slices.Sort(beta)
	if want := []string{"client:add", "domain:add", "domain:add", "domain:delete", "group:add"}; !slices.Equal(beta, want) {
		t.Errorf("beta %v, want %v", beta, want)
	}
	if d := ge.ph["beta"].Domains(); len(d) != 2 {
		t.Errorf("beta's domains %+v", d)
	}

	// One audit row per member, through the group, with what was done.
	rows, details := ge.auditSince(before)
	if len(rows) != 2 {
		t.Fatalf("%d audit rows", len(rows))
	}
	for i, r := range rows {
		if r.Action != audit.ActionGroupReconcile || r.Target != ge.target || details[i]["via"] != ge.target || r.Result != audit.ResultSuccess {
			t.Errorf("audit %+v %v", r, details[i])
		}
	}
	i := slices.IndexFunc(rows, func(r db.AuditLog) bool { return r.InstanceName == "beta" })
	if i < 0 {
		t.Fatal("no audit row for beta")
	}
	if del, _ := details[i]["delete"].([]any); len(del) != 1 || del[0] != "domain beta-only.example (deny, exact)" {
		t.Errorf("beta's audit detail %v", details[i])
	}
}

func TestReconcileItemsAPI(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	ge.differ()
	beta := ge.ids["beta"]
	ge.ph["beta"].AddGroup("beta-group")

	res := ge.admin.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{
		Domains: &[]gen.ReconcileDomain{{InstanceId: beta, Domain: "games.example", Type: "deny", Kind: "exact"}},
		Groups:  &[]gen.ReconcileGroup{{InstanceId: beta, Name: "beta-group"}},
	})
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	out := decode[gen.ReconcileResult](t, res)
	var got []string
	for _, r := range out.Results {
		s := string(r.Item) + ":" + string(r.Action) + ":" + string(r.Status)
		if r.Error != nil {
			s += ":" + r.Error.Code
		}
		got = append(got, s)
	}
	slices.Sort(got)
	// games.example needed kids, which was created with it; beta's own group is never deleted.
	if want := []string{"domain:add:ok", "group:add:ok", "group:none:failed:not_reconcilable"}; !slices.Equal(got, want) {
		t.Errorf("results %v, want %v", got, want)
	}
	// Only what was named changed: gamma wasn't touched, and beta keeps its own entry.
	if len(ge.ph["gamma"].Domains()) != 0 || len(ge.ph["beta"].Domains()) != 2 {
		t.Errorf("gamma %+v, beta %+v", ge.ph["gamma"].Domains(), ge.ph["beta"].Domains())
	}
	if !out.Report.Drifted {
		t.Error("the report says in sync, but gamma and beta still differ")
	}
}

func TestReconcileRefusals(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	ge.differ()
	beta, alpha := ge.ids["beta"], ge.ids["alpha"]
	dom := func(id int64) *[]gen.ReconcileDomain {
		return &[]gen.ReconcileDomain{{InstanceId: id, Domain: "games.example", Type: "deny", Kind: "exact"}}
	}
	for name, body := range map[string]gen.ReconcileInput{
		"nothing":       {},
		"both":          {All: ptr(true), Domains: dom(beta)},
		"the primary":   {Domains: dom(alpha)},
		"not a member":  {Domains: dom(999)},
		"a bad domain":  {Domains: &[]gen.ReconcileDomain{{InstanceId: beta, Domain: "", Type: "deny", Kind: "exact"}}},
		"a bad client":  {Clients: &[]gen.ReconcileClient{{InstanceId: beta, Client: ""}}},
		"an empty name": {Groups: &[]gen.ReconcileGroup{{InstanceId: beta, Name: ""}}},
	} {
		if res := ge.admin.do(http.MethodPost, ge.reconcilePath(), body); res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	writes := len(ge.ph["beta"].Requests())

	// drift.view isn't enough, nor are domains.edit and clients.edit; drift.reconcile alone is.
	for _, c := range []*client{
		ge.userWith("watcher", rbac.DriftView),
		ge.userWith("editor", rbac.DomainsEdit, rbac.ClientsEdit),
	} {
		res := c.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{All: ptr(true)})
		if res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != "drift.reconcile" {
			t.Errorf("%d %s", res.Code, res.Body)
		}
	}
	if len(ge.ph["beta"].Requests()) != writes {
		t.Error("a refused reconcile reached beta")
	}
	reconciler := ge.userWith("reconciler", rbac.DriftReconcile)
	mustStatus(t, reconciler.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{Domains: dom(beta)}), http.StatusOK)

	// Without the primary nothing is changed, and the answer says the primary failed.
	ge.down("alpha")
	res := ge.admin.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{All: ptr(true)})
	if res.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if d := errorDetails(t, res); d["instance"] != "alpha" || d["group"] != "site" || d["primary"] != true {
		t.Errorf("details %v", d)
	}
}

func TestReconcileMemberDown(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	ge.differ()
	ge.down("gamma")
	before := ge.auditCount()
	res := ge.admin.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{All: ptr(true)})
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	out := decode[gen.ReconcileResult](t, res)
	if m := out.Members[1]; m.Instance != "gamma" || m.Status != "failed" || m.Error == nil {
		t.Errorf("gamma %+v", m)
	}
	rows, details := ge.auditSince(before)
	for i, r := range rows {
		if r.InstanceName == "gamma" && (r.Result != audit.ResultFailure || details[i]["error_code"] != "pihole_status_error") {
			t.Errorf("gamma's audit row %+v %v", r, details[i])
		}
	}
}
