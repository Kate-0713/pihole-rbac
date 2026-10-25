// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientreset

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const password = "app-password"

var t0 = time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)

type passwords struct{}

func (passwords) InstancePassword(string) (secrets.Value, bool) {
	return secrets.NewValue([]byte(password)), true
}
func (passwords) Cipher() *secrets.Cipher { return nil }

// env is three enabled instances on fake Pi-holes: alpha and beta in the mirrored group "site" (alpha the primary),
// and gamma on its own; plus "lab", an independent group holding gamma.
type env struct {
	t      *testing.T
	ctx    context.Context
	st     *store.Store
	inst   *instances.Service
	svc    *Service
	ph     map[string]*piholetest.Server
	ids    map[string]int64
	site   int64
	lab    int64
	admin  rbac.Actor // builtin admin
	runner rbac.Actor // clientreset.run only
	sunk   *sink
}

// sink keeps the entries the audit logger hands on, as the notifier would get them.
type sink struct {
	mu      sync.Mutex
	entries []audit.Entry
}

func (s *sink) add(e audit.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

func (s *sink) all() []audit.Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	pool := instances.New(instances.Options{Passwords: passwords{}, Timeout: 2 * time.Second, Logger: logger})
	t.Cleanup(func() { pool.Close(context.Background()) })
	auditLog := audit.NewLogger(io.Discard)
	e := &env{t: t, ctx: ctx, st: st, ph: map[string]*piholetest.Server{}, ids: map[string]int64{}, sunk: &sink{}}
	auditLog.SetSink(e.sunk.add)
	e.inst = &instances.Service{Store: st, Audit: auditLog, Pool: pool, Now: func() time.Time { return t0 }}
	e.svc = &Service{Store: st, Audit: auditLog, Instances: e.inst, Logger: logger, Now: func() time.Time { return t0 }}

	if err := st.WithTx(ctx, func(q *db.Queries) error {
		adminRole, err := q.GetBuiltinRole(ctx)
		if err != nil {
			return err
		}
		runRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "runner", CreatedAt: 1})
		if err != nil {
			return err
		}
		if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: runRole, Permission: string(rbac.ClientResetRun)}); err != nil {
			return err
		}
		mk := func(name string, role int64) rbac.Actor {
			u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			return rbac.Actor{UserID: u.ID, Username: name, RoleIDs: []int64{role}, IP: "192.0.2.1"}
		}
		e.admin, e.runner = mk("alice", adminRole.ID), mk("rita", runRole)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, n := range []string{"alpha", "beta", "gamma"} {
		ph := piholetest.New(t, password)
		pw := secrets.NewValue([]byte(password))
		inst, err := e.inst.Create(ctx, e.admin, instances.Input{Name: n, BaseURL: ph.URL, EnvName: strings.ToUpper(n), Password: &pw})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.inst.SetEnabled(ctx, e.admin, inst.ID, true); err != nil {
			t.Fatal(err)
		}
		e.ph[n], e.ids[n] = ph, inst.ID
	}
	g, err := e.inst.CreateGroup(ctx, e.admin, instances.GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: e.ids["alpha"],
		Members: []int64{e.ids["alpha"], e.ids["beta"]}})
	if err != nil {
		t.Fatal(err)
	}
	e.site = g.ID
	lab, err := e.inst.CreateGroup(ctx, e.admin, instances.GroupInput{Name: "lab", Mode: rbac.Independent, Members: []int64{e.ids["gamma"]}})
	if err != nil {
		t.Fatal(err)
	}
	e.lab = lab.ID
	return e
}

func (e *env) setRules(in ...RuleInput) Settings {
	e.t.Helper()
	got, err := e.svc.SetRules(e.ctx, e.admin, in)
	if err != nil {
		e.t.Fatalf("SetRules: %v", err)
	}
	return got
}

func (e *env) auditRows(action string) []db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []db.AuditLog
	for _, r := range rows {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

func detailOf(t *testing.T, row db.AuditLog) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func client(ph *piholetest.Server, id string) piholetest.Client {
	i := slices.IndexFunc(ph.Clients(), func(c piholetest.Client) bool { return c.Client == id })
	if i < 0 {
		return piholetest.Client{}
	}
	return ph.Clients()[i]
}

func code(err error) string {
	if re, ok := rbac.AsError(err); ok {
		return string(re.Code)
	}
	return ""
}

func field(err error) string {
	if re, ok := rbac.AsError(err); ok {
		f, _ := re.Details["field"].(string)
		return f
	}
	return ""
}

func TestSetRules(t *testing.T) {
	e := newEnv(t)
	got := e.setRules(
		RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab", "AUTOSET-lab"}},
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "NINJA-", Match: MatchPrefixes, Groups: []string{"AUTOSET-"}},
	)
	if len(got.Rules) != 2 || got.Rules[0].ScopeName != "gamma" || got.Rules[1].ScopeName != "site" ||
		!slices.Equal(got.Rules[1].Groups, []string{"AUTOSET-lab"}) || got.Rules[0].Match != MatchPrefixes {
		t.Fatalf("rules %+v", got.Rules)
	}
	if len(got.Instances) != 3 || len(got.Groups) != 1 || got.Groups[0].Name != "site" {
		t.Errorf("choices %+v %+v (the independent group isn't one)", got.Instances, got.Groups)
	}
	rows := e.auditRows(audit.ActionClientResetRules)
	if len(rows) != 1 || rows[0].Username != "alice" || rows[0].Target != "client_reset:rules" {
		t.Fatalf("audit %+v", rows)
	}
	if d := detailOf(t, rows[0]); !strings.Contains(rows[0].Detail, `"NINJA- → AUTOSET- (prefixes) on gamma"`) ||
		!strings.Contains(rows[0].Detail, `"TEST- → AUTOSET-lab on site"`) || d["removed"] != nil {
		t.Errorf("detail %s", rows[0].Detail)
	}

	// The same rules again: nothing changes, and nothing is audited.
	e.setRules(
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "NINJA-", Match: MatchPrefixes, Groups: []string{"AUTOSET-"}},
		RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
	)
	if n := len(e.auditRows(audit.ActionClientResetRules)); n != 1 {
		t.Errorf("an unchanged save was audited: %d rows", n)
	}
	// One changed: one added and one removed.
	e.setRules(RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-staff"}})
	last := e.auditRows(audit.ActionClientResetRules)[0]
	if !strings.Contains(last.Detail, `"added":["TEST- → AUTOSET-staff on site"]`) ||
		!strings.Contains(last.Detail, `"removed":["NINJA- → AUTOSET- (prefixes) on gamma","TEST- → AUTOSET-lab on site"]`) {
		t.Errorf("detail %s", last.Detail)
	}

	// The rules are what blocks deleting an instance or group.
	if err := e.inst.DeleteGroup(e.ctx, e.admin, e.site); code(err) != "conflict" {
		t.Errorf("deleting a group with rules: %v", err)
	}
}

func TestSetRulesRefusals(t *testing.T) {
	e := newEnv(t)
	ok := func() RuleInput {
		return RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"g"}}
	}
	with := func(f func(r *RuleInput)) []RuleInput {
		r := ok()
		f(&r)
		return []RuleInput{r}
	}
	long := strings.Repeat("x", 256)
	for _, tc := range []struct {
		name  string
		in    []RuleInput
		field string
	}{
		{"no scope", with(func(r *RuleInput) { r.Scope = "" }), "scope"},
		{"empty prefix", with(func(r *RuleInput) { r.Prefix = "" }), "comment_prefix"},
		{"blank prefix", with(func(r *RuleInput) { r.Prefix = "   " }), "comment_prefix"},
		{"prefix with a newline", with(func(r *RuleInput) { r.Prefix = "TEST-\n" }), "comment_prefix"},
		{"long prefix", with(func(r *RuleInput) { r.Prefix = long }), "comment_prefix"},
		{"no match mode", with(func(r *RuleInput) { r.Match = "" }), "group_match"},
		{"no groups", with(func(r *RuleInput) { r.Groups = nil }), "pihole_groups"},
		{"empty group", with(func(r *RuleInput) { r.Groups = []string{""} }), "pihole_groups"},
		{"long group", with(func(r *RuleInput) { r.Groups = []string{long} }), "pihole_groups"},
		{"same prefix twice on one scope", []RuleInput{ok(), ok()}, "comment_prefix"},
		{"missing instance", with(func(r *RuleInput) { r.ID = 999 }), "id"},
		{"missing group", with(func(r *RuleInput) { r.Scope, r.ID = ScopeGroup, 999 }), "id"},
		{"independent group", with(func(r *RuleInput) { r.Scope, r.ID = ScopeGroup, e.lab }), "id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.svc.SetRules(e.ctx, e.admin, tc.in); code(err) != "validation_failed" || field(err) != tc.field {
				t.Errorf("err %v (field %q), want validation_failed on %s", err, field(err), tc.field)
			}
		})
	}
	// The same prefix on an instance and on a group is fine.
	e.setRules(ok(), RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"g"}})
	if n := len(e.auditRows(audit.ActionClientResetRules)); n != 1 {
		t.Errorf("%d audit rows, want only the good save", n)
	}

	// Without settings.manage: refused, and recorded.
	if _, err := e.svc.SetRules(e.ctx, e.runner, []RuleInput{ok()}); code(err) != "forbidden" {
		t.Fatalf("runner: %v", err)
	}
	denied := e.auditRows(audit.ActionPermissionDenied)
	if len(denied) != 1 || denied[0].Username != "rita" || !strings.Contains(denied[0].Detail, `"attempted":"client_reset_rules"`) {
		t.Errorf("denied %+v", denied)
	}
	if got, _ := e.svc.Rules(e.ctx); len(got.Rules) != 2 {
		t.Errorf("rules changed by a refused save: %+v", got.Rules)
	}
}

// gammaSetup gives gamma the groups AUTOSET-lab, AUTOSET-staff and kids, and these clients: TEST-laptop in kids,
// TEST-done already in AUTOSET-lab, NINJA-tv in Default, and Kitchen in kids.
func (e *env) gammaSetup() (lab, staff, kids int) {
	ph := e.ph["gamma"]
	lab, staff, kids = ph.AddGroup("AUTOSET-lab"), ph.AddGroup("AUTOSET-staff"), ph.AddGroup("kids")
	ph.AddClient(piholetest.Client{Client: "10.0.0.1", Comment: "TEST-laptop", Groups: []int{kids}})
	ph.AddClient(piholetest.Client{Client: "10.0.0.2", Comment: "TEST-done", Groups: []int{lab}})
	ph.AddClient(piholetest.Client{Client: "10.0.0.3", Comment: "NINJA-tv"})
	ph.AddClient(piholetest.Client{Client: "10.0.0.4", Comment: "Kitchen", Groups: []int{kids}})
	e.setRules(
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "NINJA-", Match: MatchPrefixes, Groups: []string{"AUTOSET-"}},
	)
	return lab, staff, kids
}

func TestRunInstance(t *testing.T) {
	e := newEnv(t)
	lab, staff, kids := e.gammaSetup()
	e.svc.Protected = func(_ context.Context, id int64) ([]string, error) {
		if id != e.ids["gamma"] {
			t.Errorf("protected groups asked for instance %d", id)
		}
		return []string{"autoset-STAFF"}, nil // matched ignoring case, as for client updates
	}
	gamma := rbac.InstanceTarget(e.ids["gamma"])

	// A preview changes nothing.
	pv, err := e.svc.Preview(e.ctx, gamma)
	if err != nil {
		t.Fatal(err)
	}
	if pv.TargetName != "gamma" || pv.Rules != 2 || len(pv.Instances) != 1 || len(pv.Instances[0].Reset) != 2 || pv.Instances[0].Unchanged != 1 {
		t.Fatalf("preview %+v", pv)
	}
	if c := client(e.ph["gamma"], "10.0.0.1"); !slices.Equal(c.Groups, []int{kids}) {
		t.Fatalf("a preview changed a client: %+v", c)
	}

	run, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != StatusOK || run.Target != gamma.String() || run.TargetName != "gamma" || run.Username != "rita" ||
		run.Trigger != TriggerManual || !run.StartedAt.Equal(t0) || !run.FinishedAt.Equal(t0) {
		t.Errorf("run %+v", run)
	}
	res := run.Summary.Instances[0]
	if res.Status != StatusOK || len(res.Reset) != 2 || res.Unchanged != 1 || len(res.Failed) != 0 {
		t.Fatalf("result %+v", res)
	}
	if c := client(e.ph["gamma"], "10.0.0.1"); !slices.Equal(c.Groups, []int{lab}) || c.Comment != "TEST-laptop" {
		t.Errorf("laptop %+v, want AUTOSET-lab with its comment kept", c)
	}
	if c := client(e.ph["gamma"], "10.0.0.3"); !slices.Equal(c.Groups, []int{lab, staff}) {
		t.Errorf("tv %+v, want every AUTOSET- group", c)
	}
	if c := client(e.ph["gamma"], "10.0.0.4"); !slices.Equal(c.Groups, []int{kids}) {
		t.Errorf("a client no rule matches was changed: %+v", c)
	}
	// TEST-done was already right: not sent.
	for _, r := range e.ph["gamma"].Requests() {
		if strings.Contains(r, "10.0.0.2") && strings.HasPrefix(r, "PUT") {
			t.Errorf("an unchanged client was written: %s", r)
		}
	}

	// The run is recorded, with one audit row for the instance.
	runs, err := e.svc.Runs(e.ctx, "", 0, 10)
	if err != nil || len(runs) != 1 || runs[0].ID != run.ID || runs[0].Status != StatusOK || len(runs[0].Summary.Instances[0].Reset) != 2 {
		t.Fatalf("runs %+v %v", runs, err)
	}
	rows := e.auditRows(audit.ActionClientReset)
	if len(rows) != 1 || rows[0].Username != "rita" || rows[0].Target != gamma.String() || rows[0].InstanceName != "gamma" ||
		rows[0].Result != audit.ResultSuccess {
		t.Fatalf("audit %+v", rows)
	}
	d := detailOf(t, rows[0])
	if d["summary"] != "2 clients reset" || d["trigger"] != "manual" || d["unchanged"] != 1.0 || d["via"] != nil {
		t.Errorf("detail %s", rows[0].Detail)
	}
	// NINJA-tv was put in AUTOSET-staff, which is protected: the notifier gets the alert.
	sent := e.sunk.all()
	last := sent[len(sent)-1]
	alerts := notify.ProtectedAlerts(last)
	if len(alerts) != 1 || alerts[0].Client != "10.0.0.3" || !slices.Equal(alerts[0].Groups, []string{"AUTOSET-staff"}) {
		t.Errorf("alerts %+v", alerts)
	}
	if m := notify.ForEntry(last).Plain(); m != "rita client reset on i-3 (gamma): 2 clients reset — succeeded" {
		t.Errorf("message %q", m)
	}

	// Run again: everything is as the rules say, so nothing is written or audited, but the run is recorded.
	again, err := e.svc.Run(e.ctx, SystemActor, TriggerSchedule, gamma)
	if err != nil || again.Status != StatusOK || again.Summary.Instances[0].Unchanged != 3 || again.Username != audit.SystemUser {
		t.Fatalf("second run %+v %v", again, err)
	}
	if n := len(e.auditRows(audit.ActionClientReset)); n != 1 {
		t.Errorf("%d client_reset rows, want 1", n)
	}
}

func TestRunGroup(t *testing.T) {
	e := newEnv(t)
	// The same group names on both members, under different IDs.
	alpha, beta := e.ph["alpha"], e.ph["beta"]
	alpha.AddGroup("padding")
	labA, kidsA := alpha.AddGroup("AUTOSET-lab"), alpha.AddGroup("kids")
	kidsB, labB := beta.AddGroup("kids"), beta.AddGroup("AUTOSET-lab")
	alpha.AddClient(piholetest.Client{Client: "10.0.0.1", Comment: "TEST-laptop", Groups: []int{kidsA}})
	beta.AddClient(piholetest.Client{Client: "10.0.0.1", Comment: "TEST-laptop", Groups: []int{kidsB}})
	beta.AddClient(piholetest.Client{Client: "10.0.0.9", Comment: "TEST-only-beta", Groups: []int{0}})
	e.setRules(RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}})

	site := rbac.GroupTarget(e.site)
	run, err := e.svc.Run(e.ctx, e.runner, TriggerManual, site)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != StatusOK || run.TargetName != "site" || len(run.Summary.Instances) != 2 ||
		run.Summary.Instances[0].Instance != "alpha" || !run.Summary.Instances[0].Primary {
		t.Fatalf("run %+v", run)
	}
	if c := client(alpha, "10.0.0.1"); !slices.Equal(c.Groups, []int{labA}) {
		t.Errorf("alpha laptop %+v, want its own AUTOSET-lab %d", c, labA)
	}
	if c := client(beta, "10.0.0.1"); !slices.Equal(c.Groups, []int{labB}) {
		t.Errorf("beta laptop %+v, want its own AUTOSET-lab %d", c, labB)
	}
	// Each member's own clients are matched: a client only beta has is reset there.
	if c := client(beta, "10.0.0.9"); !slices.Equal(c.Groups, []int{labB}) {
		t.Errorf("beta's own client %+v", c)
	}
	rows := e.auditRows(audit.ActionClientReset)
	if len(rows) != 2 {
		t.Fatalf("%d audit rows, want one per member", len(rows))
	}
	for _, r := range rows {
		if r.Target != site.String() || detailOf(t, r)["via"] != site.String() {
			t.Errorf("row %+v", r)
		}
	}

	// A member without the group: nothing changes there, the others go ahead, and the run is partial.
	beta.AddClient(piholetest.Client{Client: "10.0.0.10", Comment: "TEST-new", Groups: []int{kidsB}})
	alpha.AddClient(piholetest.Client{Client: "10.0.0.10", Comment: "TEST-new", Groups: []int{kidsA}})
	e.setRules(RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab", "padding"}})
	run, err = e.svc.Run(e.ctx, e.runner, TriggerManual, site)
	if err != nil {
		t.Fatal(err)
	}
	a, b := run.Summary.Instances[0], run.Summary.Instances[1]
	if run.Status != StatusPartial || a.Status != StatusOK || len(a.Reset) != 2 || b.Status != StatusFailed ||
		len(b.Failed) != 3 || b.Failed[0].Code != CodeGroupMissing || len(b.Problems) != 1 ||
		!slices.Equal(b.Problems[0].Missing, []string{"padding"}) {
		t.Fatalf("run %+v\nalpha %+v\nbeta %+v", run, a, b)
	}
	if c := client(beta, "10.0.0.10"); !slices.Equal(c.Groups, []int{kidsB}) {
		t.Errorf("beta's client was changed though its groups are missing: %+v", c)
	}
	failed := e.auditRows(audit.ActionClientReset)[0]
	if failed.InstanceName != "beta" || failed.Result != audit.ResultFailure || detailOf(t, failed)["error_code"] != CodeGroupMissing {
		t.Errorf("beta's row %+v", failed)
	}
}

func TestRunMember(t *testing.T) {
	e := newEnv(t)
	lab := e.ph["beta"].AddGroup("AUTOSET-lab")
	e.ph["beta"].AddClient(piholetest.Client{Client: "10.0.0.1", Comment: "TEST-x"})
	e.setRules(RuleInput{Scope: ScopeInstance, ID: e.ids["beta"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}})
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, rbac.InstanceTarget(e.ids["beta"])); err != nil {
		t.Fatal(err)
	}
	if c := client(e.ph["beta"], "10.0.0.1"); !slices.Equal(c.Groups, []int{lab}) {
		t.Errorf("client %+v", c)
	}
	d := detailOf(t, e.auditRows(audit.ActionClientReset)[0])
	if d["mirrored_member"] != true || d["mirrored_group"] != "site" {
		t.Errorf("a run on a member of a mirrored group isn't flagged: %v", d)
	}
}

func TestRunFailures(t *testing.T) {
	e := newEnv(t)
	e.gammaSetup()
	gamma := rbac.InstanceTarget(e.ids["gamma"])
	// Pi-hole refuses one client: the other is still reset.
	e.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && strings.Contains(r.URL.Path, "10.0.0.1") {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":{"key":"bad_request","message":"nope"}}`))
			return true
		}
		return false
	})
	run, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma)
	if err != nil {
		t.Fatal(err)
	}
	res := run.Summary.Instances[0]
	if run.Status != StatusPartial || res.Status != StatusPartial || len(res.Reset) != 1 || res.Reset[0].Client != "10.0.0.3" ||
		len(res.Failed) != 1 || res.Failed[0].Code != "pihole_rejected" {
		t.Fatalf("run %+v %+v", run, res)
	}
	row := e.auditRows(audit.ActionClientReset)[0]
	if row.Result != audit.ResultFailure || detailOf(t, row)["summary"] != "1 client reset, 1 failed" {
		t.Errorf("row %+v", row)
	}

	// The instance doesn't answer at all.
	e.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	})
	run, err = e.svc.Run(e.ctx, e.runner, TriggerManual, gamma)
	if err != nil {
		t.Fatal(err)
	}
	res = run.Summary.Instances[0]
	if run.Status != StatusFailed || res.Status != StatusFailed || res.Code != "pihole_status_error" || len(res.Failed) != 0 {
		t.Fatalf("run %+v %+v", run, res)
	}
	if d := detailOf(t, e.auditRows(audit.ActionClientReset)[0]); d["summary"] != "couldn't use the instance (pihole_status_error)" ||
		d["error_code"] != "pihole_status_error" {
		t.Errorf("detail %v", d)
	}
}

func TestRunRefusals(t *testing.T) {
	e := newEnv(t)
	gamma := rbac.InstanceTarget(e.ids["gamma"])
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma); code(err) != "conflict" {
		t.Errorf("no rules: %v", err)
	}
	if _, err := e.svc.Preview(e.ctx, gamma); code(err) != "conflict" {
		t.Errorf("preview with no rules: %v", err)
	}
	e.gammaSetup()
	if _, err := e.inst.SetEnabled(e.ctx, e.admin, e.ids["gamma"], false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma); code(err) != "not_found" {
		t.Errorf("disabled instance: %v", err)
	}
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, rbac.GroupTarget(e.lab)); code(err) != "not_found" {
		t.Errorf("independent group: %v", err)
	}
	if runs, _ := e.svc.Runs(e.ctx, "", 0, 10); len(runs) != 0 {
		t.Errorf("refused runs were recorded: %+v", runs)
	}
}

func TestOneRunAtATime(t *testing.T) {
	e := newEnv(t)
	e.gammaSetup()
	gamma := rbac.InstanceTarget(e.ids["gamma"])
	// A run left running by a process that stopped.
	if err := e.st.WithTx(e.ctx, func(q *db.Queries) error {
		_, err := q.StartClientResetRun(e.ctx, db.StartClientResetRunParams{
			StartedAt: store.Millis(t0), Trigger: "schedule", Username: audit.SystemUser, Target: "g-1", TargetName: "site",
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma); code(err) != "conflict" ||
		!strings.Contains(err.Error(), "already running") {
		t.Fatalf("while another runs: %v", err)
	}
	if n, err := e.svc.FailInterrupted(e.ctx); err != nil || n != 1 {
		t.Fatalf("FailInterrupted = %d, %v", n, err)
	}
	if n, _ := e.svc.FailInterrupted(e.ctx); n != 0 {
		t.Errorf("FailInterrupted again = %d", n)
	}
	if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, gamma); err != nil {
		t.Fatalf("after recovering: %v", err)
	}
	runs, err := e.svc.Runs(e.ctx, "", 0, 10)
	if err != nil || len(runs) != 2 {
		t.Fatalf("runs %+v %v", runs, err)
	}
	if old := runs[1]; old.Status != StatusFailed || !strings.Contains(old.Summary.Error, "interrupted") || old.FinishedAt.IsZero() {
		t.Errorf("interrupted run %+v", old)
	}
}

func TestRunsListing(t *testing.T) {
	e := newEnv(t)
	e.gammaSetup()
	e.ph["beta"].AddGroup("AUTOSET-lab")
	e.ph["alpha"].AddGroup("AUTOSET-lab")
	e.setRules(
		RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
		RuleInput{Scope: ScopeGroup, ID: e.site, Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}},
	)
	gamma, site := rbac.InstanceTarget(e.ids["gamma"]), rbac.GroupTarget(e.site)
	for _, tg := range []rbac.Target{gamma, site, gamma, site, gamma} {
		if _, err := e.svc.Run(e.ctx, e.runner, TriggerManual, tg); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := e.svc.Runs(e.ctx, "", 0, 50)
	onGamma, _ := e.svc.Runs(e.ctx, gamma.String(), 0, 50)
	if len(all) != 5 || len(onGamma) != 3 || all[0].ID < all[1].ID {
		t.Fatalf("all %d, on gamma %d", len(all), len(onGamma))
	}
	page, _ := e.svc.Runs(e.ctx, gamma.String(), onGamma[0].ID, 1)
	if len(page) != 1 || page[0].ID != onGamma[1].ID {
		t.Errorf("paging %+v", page)
	}
	got, err := e.svc.GetRun(e.ctx, all[0].ID)
	if err != nil || got.ID != all[0].ID {
		t.Errorf("GetRun %+v %v", got, err)
	}
	if _, err := e.svc.GetRun(e.ctx, 999); code(err) != "not_found" {
		t.Errorf("missing run: %v", err)
	}

	// Deleting the group keeps its runs, under its name.
	e.setRules(RuleInput{Scope: ScopeInstance, ID: e.ids["gamma"], Prefix: "TEST-", Match: MatchNames, Groups: []string{"AUTOSET-lab"}})
	if err := e.inst.DeleteGroup(e.ctx, e.admin, e.site); err != nil {
		t.Fatal(err)
	}
	onSite, _ := e.svc.Runs(e.ctx, site.String(), 0, 50)
	if len(onSite) != 2 || onSite[0].TargetName != "site" {
		t.Errorf("runs of a deleted group %+v", onSite)
	}
}
