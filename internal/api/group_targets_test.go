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

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// groupEnv is a server with three enabled instances on fake Pi-holes, alpha (the primary), beta and gamma, in the
// mirrored group "site", and a logged-in admin.
type groupEnv struct {
	*testEnv
	admin   *client
	ph      map[string]*piholetest.Server
	ids     map[string]int64
	groupID int64
	target  string
}

func newGroupEnv(t *testing.T, modify ...func(*Options)) *groupEnv {
	t.Helper()
	names := []string{"alpha", "beta", "gamma"}
	env := map[string]string{}
	for _, n := range names {
		env[secrets.InstanceVar(strings.ToUpper(n))] = piholePassword
	}
	e := newTestEnv(t, append([]func(*Options){withInstances(t, env)}, modify...)...)
	e.addUser("admin", "admin-password-1", true)
	ge := &groupEnv{testEnv: e, admin: e.loggedIn("admin", "admin-password-1"), ph: map[string]*piholetest.Server{}, ids: map[string]int64{}}
	for _, n := range names {
		ph := piholetest.New(t, piholePassword)
		res := ge.admin.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: n, BaseUrl: ph.URL, EnvName: ptr(strings.ToUpper(n)), Password: ptr(piholePassword)})
		mustStatus(t, res, http.StatusCreated)
		id := decode[gen.Instance](t, res).Id
		mustStatus(t, ge.admin.do(http.MethodPost, instancePath(id, "/enable"), nil), http.StatusOK)
		ge.ph[n], ge.ids[n] = ph, id
	}
	res := ge.admin.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{
		Name: "site", Mode: "mirrored", Members: []int64{ge.ids["gamma"], ge.ids["beta"], ge.ids["alpha"]}, PrimaryInstanceId: ptr(ge.ids["alpha"]),
	})
	mustStatus(t, res, http.StatusCreated)
	ge.groupID = decode[gen.InstanceGroup](t, res).Id
	ge.target = "g-" + strconv.FormatInt(ge.groupID, 10)
	return ge
}

func (ge *groupEnv) path(suffix string) string { return "/api/v1/targets/" + ge.target + suffix }

func (ge *groupEnv) instPath(name, suffix string) string {
	return "/api/v1/targets/i-" + strconv.FormatInt(ge.ids[name], 10) + suffix
}

// unreachable makes a fake Pi-hole drop every connection, so the app finds it down.
func (ge *groupEnv) unreachable(name string) {
	ge.ph[name].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
			conn.Close()
		}
		return true
	})
}

// down makes a fake Pi-hole answer every request with a server error, as a broken Pi-hole would. The app counts that
// as a failure, but not as the Pi-hole being down: it did answer.
func (ge *groupEnv) down(name string) {
	ge.ph[name].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	})
}

// auditSince returns the audit rows written after the first n, with their details decoded.
func (ge *groupEnv) auditSince(n int) ([]db.AuditLog, []map[string]any) {
	ge.t.Helper()
	rows := ge.auditRows()[n:]
	details := make([]map[string]any, len(rows))
	for i, r := range rows {
		if err := json.Unmarshal([]byte(r.Detail), &details[i]); err != nil {
			ge.t.Fatal(err)
		}
	}
	return rows, details
}

type resultRow struct {
	Instance string `json:"instance"`
	Status   string `json:"status"`
	Error    *struct {
		Code string `json:"code"`
	} `json:"error"`
}

func results(t *testing.T, res response) []resultRow {
	t.Helper()
	var body struct {
		Results []resultRow `json:"results"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Results
}

func summarise(rows []resultRow) []string {
	var out []string
	for _, r := range rows {
		s := r.Instance + ":" + r.Status
		if r.Error != nil {
			s += ":" + r.Error.Code
		}
		out = append(out, s)
	}
	return out
}

func TestGroupTargetsListed(t *testing.T) {
	ge := newGroupEnv(t)
	tl := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil))
	var ids []string
	for _, tg := range tl.Targets {
		ids = append(ids, tg.Id)
		if tg.Kind == gen.TargetKindInstance && (tg.MirroredGroup == nil || tg.MirroredGroup.Id != ge.target || tg.MirroredGroup.Name != "site") {
			t.Errorf("%s doesn't name its mirrored group: %+v", tg.Name, tg.MirroredGroup)
		}
	}
	if want := []string{"i-1", "i-2", "i-3", ge.target}; !slices.Equal(ids, want) {
		t.Fatalf("targets %v, want %v", ids, want)
	}
	g := tl.Targets[3]
	if g.Kind != gen.TargetKindGroup || g.Name != "site" || g.Members == nil || g.Health == nil || g.Health.State != "unknown" {
		t.Fatalf("group target %+v", g)
	}
	var members []string
	for _, m := range *g.Members {
		members = append(members, m.Name+":"+strconv.FormatBool(m.Primary))
	}
	if !slices.Equal(members, []string{"alpha:true", "beta:false", "gamma:false"}) {
		t.Errorf("members %v", members)
	}

	// After a read through the group, every member is up; one down makes the group degraded.
	mustStatus(t, ge.admin.do(http.MethodGet, ge.path("/summary"), nil), http.StatusOK)
	if g := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)).Targets[3]; g.Health.State != "up" {
		t.Errorf("health after a read: %s", g.Health.State)
	}
	ge.unreachable("gamma")
	mustStatus(t, ge.admin.do(http.MethodGet, ge.path("/summary"), nil), http.StatusOK)
	if g := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)).Targets[3]; g.Health.State != "degraded" {
		t.Errorf("health with gamma down: %s", g.Health.State)
	}

	// A disabled member is left out; a disabled primary takes the group away.
	mustStatus(t, ge.admin.do(http.MethodPost, instancePath(ge.ids["gamma"], "/disable"), nil), http.StatusOK)
	g = decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)).Targets[2]
	if g.Id != ge.target || len(*g.Members) != 2 || g.Health.State != "up" {
		t.Errorf("with gamma disabled: %+v", g)
	}
	mustStatus(t, ge.admin.do(http.MethodPost, instancePath(ge.ids["alpha"], "/disable"), nil), http.StatusOK)
	for _, tg := range decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)).Targets {
		if tg.Id == ge.target {
			t.Error("a group whose primary is disabled is listed")
		}
	}
	if res := ge.admin.do(http.MethodGet, ge.path("/domains"), nil); res.Code != http.StatusNotFound {
		t.Errorf("group with its primary disabled: %d %s", res.Code, res.Body)
	}
}

func TestGroupTargetPermissions(t *testing.T) {
	ge := newGroupEnv(t)
	res := ge.admin.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: "site editors", Grants: &[]gen.Grant{
		{Permission: string(rbac.DomainsView), Scope: "group", Id: ptr(ge.groupID)},
		{Permission: string(rbac.DomainsEdit), Scope: "group", Id: ptr(ge.groupID)},
	}})
	mustStatus(t, res, http.StatusCreated)
	role := decode[gen.Role](t, res).Id
	mustStatus(t, ge.admin.do(http.MethodPost, "/api/v1/users", gen.UserCreate{Username: "sam", Password: "sam-password-12", RoleIds: []int64{role}}), http.StatusCreated)
	sam := ge.loggedIn("sam", "sam-password-12")

	// sam acts through the group, and only through it: a grant on a mirrored group doesn't cover its members alone.
	tl := decode[gen.TargetList](t, sam.do(http.MethodGet, "/api/v1/targets", nil))
	if len(tl.Targets) != 1 || tl.Targets[0].Id != ge.target {
		t.Fatalf("sam's targets %+v", tl.Targets)
	}
	mustStatus(t, sam.do(http.MethodGet, ge.path("/domains"), nil), http.StatusOK)
	mustStatus(t, sam.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "ads.example", Type: "deny", Kind: "exact"}), http.StatusOK)
	if res := sam.do(http.MethodPost, ge.instPath("beta", "/domains"), gen.DomainInput{Domain: "x.example", Type: "deny", Kind: "exact"}); res.Code != http.StatusForbidden {
		t.Errorf("sam on beta alone: %d", res.Code)
	}
	if res := sam.do(http.MethodGet, ge.path("/queries"), nil); res.Code != http.StatusForbidden {
		t.Errorf("sam without querylog.view: %d", res.Code)
	}
}

func TestGroupReads(t *testing.T) {
	ge := newGroupEnv(t)
	ge.ph["alpha"].AddDomain(piholetest.Domain{Domain: "only-on-alpha.example", Type: "deny", Kind: "exact", Enabled: true})
	ge.ph["beta"].AddDomain(piholetest.Domain{Domain: "only-on-beta.example", Type: "deny", Kind: "exact", Enabled: true})
	ge.ph["alpha"].AddClient(piholetest.Client{Client: "10.0.0.5"})

	// Domains, clients and Pi-hole groups come from the primary alone.
	list := decode[gen.DomainList](t, ge.admin.do(http.MethodGet, ge.path("/domains"), nil))
	if len(list.Domains) != 1 || list.Domains[0].Domain != "only-on-alpha.example" {
		t.Errorf("domains %+v", list.Domains)
	}
	if cl := decode[gen.ClientList](t, ge.admin.do(http.MethodGet, ge.path("/clients"), nil)); len(cl.Clients) != 1 {
		t.Errorf("clients %+v", cl.Clients)
	}
	for _, n := range []string{"beta", "gamma"} {
		for _, r := range ge.ph[n].Requests() {
			if r == "GET /api/domains" || r == "GET /api/clients" {
				t.Errorf("%s was read: %s", n, r)
			}
		}
	}

	// The summary adds up the members; each one's blocking is listed.
	sum := decode[gen.TargetSummary](t, ge.admin.do(http.MethodGet, ge.path("/summary"), nil))
	if sum.Live.Queries != 3000 || sum.Live.Blocked != 750 || sum.Live.PercentBlocked != 25 || sum.Last24h.Queries != 60000 ||
		sum.Live.DomainsOnBlocklist != 123456 || sum.Live.Status["GRAVITY"] != 750 || sum.Blocking.Blocking != "enabled" {
		t.Errorf("summary %+v", sum)
	}
	if sum.Members == nil || len(*sum.Members) != 3 || !(*sum.Members)[0].Primary || (*sum.Members)[0].Blocking == nil {
		t.Fatalf("summary members %+v", sum.Members)
	}

	// The query log merges the members' newest entries, newest first, each naming its instance.
	q := func(t float64, domain string) piholetest.Query {
		var e piholetest.Query
		e.Time, e.Domain, e.Type, e.Status = t, domain, "A", "FORWARDED"
		e.Client.IP = "10.0.0.9"
		return e
	}
	ge.ph["alpha"].SetQueries([]piholetest.Query{q(300, "a3"), q(100, "a1")})
	ge.ph["beta"].SetQueries([]piholetest.Query{q(200, "b2")})
	ge.ph["gamma"].SetQueries([]piholetest.Query{q(400, "g4")})
	log := decode[gen.QueryLog](t, ge.admin.do(http.MethodGet, ge.path("/queries?length=3"), nil))
	var got []string
	for _, e := range log.Queries {
		got = append(got, e.Instance+"/"+e.Domain)
	}
	if !slices.Equal(got, []string{"gamma/g4", "alpha/a3", "beta/b2"}) {
		t.Errorf("merged log %v", got)
	}
	if log.Members == nil || len(*log.Members) != 3 {
		t.Errorf("log members %+v", log.Members)
	}
	// An instance's own log names it too, and has no members.
	one := decode[gen.QueryLog](t, ge.admin.do(http.MethodGet, ge.instPath("beta", "/queries"), nil))
	if len(one.Queries) != 1 || one.Queries[0].Instance != "beta" || one.Members != nil {
		t.Errorf("beta's log %+v", one)
	}

	t.Run("a member down", func(t *testing.T) {
		ge.down("gamma")
		sum := decode[gen.TargetSummary](t, ge.admin.do(http.MethodGet, ge.path("/summary"), nil))
		if sum.Live.Queries != 2000 || (*sum.Members)[2].Status != "failed" || (*sum.Members)[2].Error == nil {
			t.Errorf("summary with gamma down: %+v %+v", sum.Live, (*sum.Members)[2])
		}
		log := decode[gen.QueryLog](t, ge.admin.do(http.MethodGet, ge.path("/queries"), nil))
		if len(log.Queries) != 3 || (*log.Members)[2].Status != "failed" {
			t.Errorf("log with gamma down: %d entries, %+v", len(log.Queries), (*log.Members)[2])
		}
	})

	t.Run("the primary down", func(t *testing.T) {
		ge.down("alpha")
		res := ge.admin.do(http.MethodGet, ge.path("/domains"), nil)
		if res.Code != http.StatusBadGateway {
			t.Fatalf("domains with the primary down: %d %s", res.Code, res.Body)
		}
		d := errorDetails(t, res)
		if d["instance"] != "alpha" || d["group"] != "site" || d["primary"] != true {
			t.Errorf("details %v", d)
		}
		// The dashboard still shows the member that answered.
		sum := decode[gen.TargetSummary](t, ge.admin.do(http.MethodGet, ge.path("/summary"), nil))
		if sum.Live.Queries != 1000 || sum.Live.DomainsOnBlocklist != 123456 {
			t.Errorf("summary with only beta: %+v", sum.Live)
		}
		ge.down("beta")
		if res := ge.admin.do(http.MethodGet, ge.path("/summary"), nil); res.Code != http.StatusBadGateway || errorDetails(t, res)["instance"] != "alpha" {
			t.Errorf("summary with every member down: %d %s", res.Code, res.Body)
		}
	})
}

func TestGroupBlocking(t *testing.T) {
	ge := newGroupEnv(t)
	before := ge.auditCount()
	res := ge.admin.do(http.MethodPut, ge.path("/blocking"), gen.BlockingInput{Enabled: false, Timer: ptr(300)})
	mustStatus(t, res, http.StatusOK)
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:ok"}) {
		t.Errorf("results %v", got)
	}
	for n, ph := range ge.ph {
		if on, _ := ph.Blocking(); on {
			t.Errorf("%s still blocking", n)
		}
	}
	rows, details := ge.auditSince(before)
	if len(rows) != 3 {
		t.Fatalf("%d audit rows", len(rows))
	}
	for i, r := range rows {
		if r.Action != audit.ActionBlockingSet || r.Target != ge.target || details[i]["via"] != ge.target || !r.InstanceID.Valid {
			t.Errorf("audit row %+v %v", r, details[i])
		}
	}

	// Members that differ show as mixed.
	mustStatus(t, ge.admin.do(http.MethodPut, ge.instPath("beta", "/blocking"), gen.BlockingInput{Enabled: true}), http.StatusOK)
	if st := decode[gen.BlockingStatus](t, ge.admin.do(http.MethodGet, ge.path("/blocking"), nil)); st.Blocking != "mixed" || st.Timer != nil {
		t.Errorf("blocking %+v", st)
	}
	_, details = ge.auditSince(ge.auditCount() - 1)
	if details[0]["mirrored_member"] != true || details[0]["mirrored_group"] != "site" {
		t.Errorf("a direct edit to a member isn't flagged: %v", details[0])
	}

	// One member failing gives 207; all failing gives the first failure, with every result.
	ge.down("gamma")
	res = ge.admin.do(http.MethodPost, ge.path("/dns/restart"), nil)
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("restart with gamma down: %d %s", res.Code, res.Body)
	}
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:failed:pihole_status_error"}) {
		t.Errorf("results %v", got)
	}
	ge.down("alpha")
	ge.down("beta")
	res = ge.admin.do(http.MethodPut, ge.path("/blocking"), gen.BlockingInput{Enabled: true})
	if res.Code != http.StatusBadGateway || errorDetails(t, res)["instance"] != "alpha" || errorDetails(t, res)["results"] == nil {
		t.Errorf("blocking with every member down: %d %s", res.Code, res.Body)
	}
}

func TestGroupDomainWrites(t *testing.T) {
	ge := newGroupEnv(t)
	// The same Pi-hole group has a different ID on each member, and gamma doesn't have "guests" at all.
	kidsAlpha := ge.ph["alpha"].AddGroup("kids")
	ge.ph["beta"].AddGroup("padding")
	kidsBeta := ge.ph["beta"].AddGroup("kids")
	kidsGamma := ge.ph["gamma"].AddGroup("kids")
	guestsAlpha := ge.ph["alpha"].AddGroup("guests")
	ge.ph["beta"].AddGroup("guests")
	if kidsAlpha == kidsBeta {
		t.Fatal("the test needs different IDs")
	}

	before := ge.auditCount()
	res := ge.admin.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "games.example", Type: "deny", Kind: "exact", Groups: &[]int{kidsAlpha}})
	mustStatus(t, res, http.StatusOK)
	for n, want := range map[string]int{"alpha": kidsAlpha, "beta": kidsBeta, "gamma": kidsGamma} {
		d := ge.ph[n].Domains()
		if len(d) != 1 || !slices.Equal(d[0].Groups, []int{want}) {
			t.Errorf("%s has %+v, want the entry in its kids group %d", n, d, want)
		}
	}
	if rows, _ := ge.auditSince(before); len(rows) != 3 {
		t.Errorf("%d audit rows, want one per member", len(rows))
	}

	// gamma has no "guests": it fails there, and the others get the entry.
	res = ge.admin.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "wifi.example", Type: "allow", Kind: "exact", Groups: &[]int{guestsAlpha}})
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("add with gamma missing a group: %d %s", res.Code, res.Body)
	}
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:failed:pihole_group_missing"}) {
		t.Errorf("results %v", got)
	}
	if len(ge.ph["gamma"].Domains()) != 1 {
		t.Error("gamma got the entry without its group")
	}
	// A group the primary doesn't have is the request's 400, before anything is sent.
	if res := ge.admin.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "x.example", Type: "deny", Kind: "exact", Groups: &[]int{999}}); res.Code != http.StatusBadRequest {
		t.Errorf("unknown group: %d %s", res.Code, res.Body)
	}

	t.Run("change", func(t *testing.T) {
		// wifi.example isn't on gamma: the change fails there with not_found, and gamma isn't given the entry.
		res := ge.admin.do(http.MethodPatch, ge.path("/domains"), gen.DomainUpdate{Domain: "wifi.example", Type: "allow", Kind: "exact", Comment: ptr("guest wifi")})
		if res.Code != http.StatusMultiStatus {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:failed:not_found"}) {
			t.Errorf("results %v", got)
		}
		if len(ge.ph["gamma"].Domains()) != 1 {
			t.Error("the change created the entry on gamma")
		}
		// Not on the primary: a 404, and nothing is sent.
		ge.ph["beta"].AddDomain(piholetest.Domain{Domain: "beta-only.example", Type: "deny", Kind: "exact", Enabled: true})
		writes := len(ge.ph["beta"].Requests())
		if res := ge.admin.do(http.MethodPatch, ge.path("/domains"), gen.DomainUpdate{Domain: "beta-only.example", Type: "deny", Kind: "exact", Comment: ptr("x")}); res.Code != http.StatusNotFound {
			t.Errorf("not on the primary: %d %s", res.Code, res.Body)
		}
		for _, r := range ge.ph["beta"].Requests()[writes:] {
			if r[:4] == "PUT " {
				t.Errorf("beta was changed: %s", r)
			}
		}
		// Groups are translated on a change too.
		res = ge.admin.do(http.MethodPatch, ge.path("/domains"), gen.DomainUpdate{Domain: "games.example", Type: "deny", Kind: "exact", Groups: &[]int{0, kidsAlpha}})
		mustStatus(t, res, http.StatusOK)
		if d := ge.ph["beta"].Domains()[0]; !slices.Equal(d.Groups, []int{0, kidsBeta}) {
			t.Errorf("beta's groups %v", d.Groups)
		}
	})

	t.Run("delete", func(t *testing.T) {
		// wifi.example isn't on gamma, which is already as asked.
		before := ge.auditCount()
		res := ge.admin.do(http.MethodDelete, ge.path("/domains"), gen.DomainKey{Domain: "wifi.example", Type: "allow", Kind: "exact"})
		mustStatus(t, res, http.StatusOK)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:ok"}) {
			t.Errorf("results %v", got)
		}
		if rows, _ := ge.auditSince(before); len(rows) != 2 {
			t.Errorf("%d audit rows, want two: nothing was sent to gamma", len(rows))
		}
	})

	t.Run("the primary down", func(t *testing.T) {
		ge.down("alpha")
		// Without the primary, its group IDs can't be named, so nothing is sent.
		if res := ge.admin.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "y.example", Type: "deny", Kind: "exact", Groups: &[]int{kidsAlpha}}); res.Code != http.StatusBadGateway {
			t.Errorf("groups without the primary: %d %s", res.Code, res.Body)
		}
		// A write that names no groups still goes to the others.
		res := ge.admin.do(http.MethodDelete, ge.path("/domains"), gen.DomainKey{Domain: "games.example", Type: "deny", Kind: "exact"})
		if res.Code != http.StatusMultiStatus {
			t.Fatalf("delete with the primary down: %d %s", res.Code, res.Body)
		}
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:failed:pihole_status_error", "beta:ok", "gamma:ok"}) {
			t.Errorf("results %v", got)
		}
		if len(ge.ph["beta"].Domains()) != 1 { // beta-only.example is left
			t.Errorf("beta has %+v", ge.ph["beta"].Domains())
		}
	})
}

func TestGroupClientWrites(t *testing.T) {
	ge := newGroupEnv(t)
	kidsAlpha := ge.ph["alpha"].AddGroup("kids")
	ge.ph["beta"].AddGroup("padding")
	kidsBeta := ge.ph["beta"].AddGroup("kids")
	ge.ph["alpha"].AddClient(piholetest.Client{Client: "10.0.0.5"})
	ge.ph["beta"].AddClient(piholetest.Client{Client: "10.0.0.5"})

	// gamma has neither the client nor the group; the client fails there as not_found, and isn't created.
	res := ge.admin.do(http.MethodPatch, ge.path("/clients"), gen.ClientUpdate{Client: "10.0.0.5", Groups: &[]int{kidsAlpha}})
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:failed:not_found"}) {
		t.Errorf("results %v", got)
	}
	if c := ge.ph["beta"].Clients()[0]; !slices.Equal(c.Groups, []int{kidsBeta}) {
		t.Errorf("beta's client groups %v", c.Groups)
	}
	if len(ge.ph["gamma"].Clients()) != 0 {
		t.Error("the client was created on gamma")
	}
	if res := ge.admin.do(http.MethodPatch, ge.path("/clients"), gen.ClientUpdate{Client: "10.9.9.9", Comment: ptr("x")}); res.Code != http.StatusNotFound {
		t.Errorf("a client the primary doesn't have: %d %s", res.Code, res.Body)
	}
}

func (ge *groupEnv) auditCount() int { return len(ge.auditRows()) }

// TestGroupRetryMembers: ?members= sends a group write to the members named, to retry those that failed.
func TestGroupRetryMembers(t *testing.T) {
	ge := newGroupEnv(t)
	kidsAlpha := ge.ph["alpha"].AddGroup("kids")
	ge.ph["gamma"].AddGroup("padding")
	kidsGamma := ge.ph["gamma"].AddGroup("kids")
	ge.ph["beta"].AddGroup("kids")
	add := gen.DomainInput{Domain: "games.example", Type: "deny", Kind: "exact", Groups: &[]int{kidsAlpha}}

	ge.down("gamma")
	res := ge.admin.do(http.MethodPost, ge.path("/domains"), add)
	if res.Code != http.StatusMultiStatus {
		t.Fatalf("%d %s", res.Code, res.Body)
	}

	// gamma is back: retrying it alone sends nothing to the others, and the primary's group names still apply.
	ge.ph["gamma"].Handle(func(http.ResponseWriter, *http.Request) bool { return false })
	before := ge.auditCount()
	alphaRequests := len(ge.ph["alpha"].Requests())
	res = ge.admin.do(http.MethodPost, ge.path("/domains?members="+strconv.FormatInt(ge.ids["gamma"], 10)), add)
	mustStatus(t, res, http.StatusOK)
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"gamma:ok"}) {
		t.Errorf("results %v", got)
	}
	if d := ge.ph["gamma"].Domains(); len(d) != 1 || !slices.Equal(d[0].Groups, []int{kidsGamma}) {
		t.Errorf("gamma has %+v", d)
	}
	for _, r := range ge.ph["alpha"].Requests()[alphaRequests:] {
		if r[:4] != "GET " {
			t.Errorf("alpha was changed by the retry: %s", r)
		}
	}
	rows, details := ge.auditSince(before)
	if len(rows) != 1 || rows[0].Target != ge.target || details[0]["via"] != ge.target || rows[0].InstanceName != "gamma" {
		t.Errorf("audit %+v %v", rows, details)
	}

	// Several members are named with the parameter repeated.
	res = ge.admin.do(http.MethodPut, ge.path("/blocking?members="+strconv.FormatInt(ge.ids["beta"], 10)+"&members="+strconv.FormatInt(ge.ids["alpha"], 10)), gen.BlockingInput{Enabled: false})
	mustStatus(t, res, http.StatusOK)
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok"}) {
		t.Errorf("results %v", got)
	}
	if on, _ := ge.ph["gamma"].Blocking(); !on {
		t.Error("gamma wasn't named but was changed")
	}

	for name, path := range map[string]string{
		"an instance target": ge.instPath("beta", "/blocking?members="+strconv.FormatInt(ge.ids["beta"], 10)),
		"not a member":       ge.path("/blocking?members=999"),
	} {
		if res := ge.admin.do(http.MethodPut, path, gen.BlockingInput{Enabled: true}); res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "members" {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	// A disabled member isn't one.
	mustStatus(t, ge.admin.do(http.MethodPost, instancePath(ge.ids["gamma"], "/disable"), nil), http.StatusOK)
	if res := ge.admin.do(http.MethodPut, ge.path("/blocking?members="+strconv.FormatInt(ge.ids["gamma"], 10)), gen.BlockingInput{Enabled: true}); res.Code != http.StatusBadRequest {
		t.Errorf("a disabled member: %d %s", res.Code, res.Body)
	}
}
