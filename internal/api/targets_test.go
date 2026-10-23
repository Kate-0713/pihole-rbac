// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// targetEnv is a server with one enabled instance, pihole1, backed by a fake Pi-hole, and a logged-in admin.
type targetEnv struct {
	*testEnv
	ph     *piholetest.Server
	admin  *client
	id     int64
	target string
}

func newTargetEnv(t *testing.T) *targetEnv {
	t.Helper()
	ph := piholetest.New(t, piholePassword)
	e := newTestEnv(t, withInstances(t, map[string]string{secrets.InstanceVar("PIHOLE1"): piholePassword}))
	e.addUser("admin", "admin-password-1", true)
	admin := e.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "pihole1", BaseUrl: ph.URL, EnvName: "PIHOLE1"})
	mustStatus(t, res, http.StatusCreated)
	id := decode[gen.Instance](t, res).Id
	mustStatus(t, admin.do(http.MethodPost, instancePath(id, "/enable"), nil), http.StatusOK)
	return &targetEnv{testEnv: e, ph: ph, admin: admin, id: id, target: "i-" + strconv.FormatInt(id, 10)}
}

func (te *targetEnv) path(suffix string) string {
	return "/api/v1/targets/" + te.target + suffix
}

// lastAudit returns the newest audit row, and its detail decoded.
func (te *targetEnv) lastAudit() (db.AuditLog, map[string]any) {
	te.t.Helper()
	rows := te.auditRows()
	if len(rows) == 0 {
		te.t.Fatal("no audit rows")
	}
	row := rows[len(rows)-1]
	var detail map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &detail); err != nil {
		te.t.Fatal(err)
	}
	return row, detail
}

func (te *targetEnv) auditCount() int { return len(te.auditRows()) }

// piholeWrites returns the requests that would change something on the fake Pi-hole.
func (te *targetEnv) piholeWrites() []string {
	var out []string
	for _, r := range te.ph.Requests() {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

func strp(s string) *string { return &s }
func intsp(ids ...int) *[]int {
	if ids == nil {
		ids = []int{}
	}
	return &ids
}

// TestTargetAccess: every target endpoint checks its permission on the target itself, a user with nothing on a
// target gets a 403 whether it exists or not, and malformed, group and disabled targets are refused before Pi-hole
// is asked anything.
func TestTargetAccess(t *testing.T) {
	te := newTargetEnv(t)
	domain := gen.DomainKey{Domain: "ads.example", Type: "deny", Kind: "exact"}
	ops := []struct {
		method, suffix string
		body           any
		perm           rbac.Permission // "" for any permission on the target
	}{
		{http.MethodGet, "/summary", nil, ""},
		{http.MethodGet, "/blocking", nil, ""},
		{http.MethodPut, "/blocking", gen.BlockingInput{Enabled: true}, rbac.BlockingToggle},
		{http.MethodPost, "/dns/restart", nil, rbac.DNSRestart},
		{http.MethodGet, "/domains", nil, rbac.DomainsView},
		{http.MethodPost, "/domains", gen.DomainInput{Domain: "ads.example", Type: "deny", Kind: "exact"}, rbac.DomainsEdit},
		{http.MethodPatch, "/domains", gen.DomainUpdate{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: strp("x")}, rbac.DomainsEdit},
		{http.MethodDelete, "/domains", domain, rbac.DomainsEdit},
		{http.MethodGet, "/clients", nil, rbac.ClientsView},
		{http.MethodPatch, "/clients", gen.ClientUpdate{Client: "10.0.0.5", Comment: strp("x")}, rbac.ClientsEdit},
		{http.MethodGet, "/groups", nil, ""},
		{http.MethodGet, "/queries", nil, rbac.QueryLogView},
	}

	// A user who holds querylog.view on pihole1 only: enough for the "any permission" reads, nothing else.
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.QueryLogView, "instance", te.id))
	viewer := te.loggedIn("viewer", "viewer-password-1")
	// A user with a global permission only, so nothing on any target.
	te.addGrantUser("other", "other-password-1", grant(rbac.AuditView, "all", 0))
	other := te.loggedIn("other", "other-password-1")
	anon := te.client("10.0.0.9:1")
	anon.fetchCSRF()

	for _, op := range ops {
		name := op.method + " " + op.suffix
		t.Run(name, func(t *testing.T) {
			// None of these reach the Pi-hole.
			before := len(te.ph.Requests())
			if res := anon.do(op.method, te.path(op.suffix), op.body); res.Code != http.StatusUnauthorized {
				t.Errorf("no session: %d, want 401", res.Code)
			}
			res := other.do(op.method, te.path(op.suffix), op.body)
			if res.Code != http.StatusForbidden || res.errorCode() != "forbidden" {
				t.Errorf("no permission on the target: %d %s", res.Code, res.Body)
			}
			// A target that doesn't exist looks the same as one the user can't use.
			if res := other.do(op.method, "/api/v1/targets/i-999"+op.suffix, op.body); res.Code != http.StatusForbidden {
				t.Errorf("missing target: %d, want 403", res.Code)
			}
			for _, bad := range []string{"x-1", "i-01", "i-", "i-1x"} {
				if res := te.admin.do(op.method, "/api/v1/targets/"+bad+op.suffix, op.body); res.Code != http.StatusBadRequest {
					t.Errorf("target %q: %d, want 400", bad, res.Code)
				}
			}
			if res := te.admin.do(op.method, "/api/v1/targets/g-1"+op.suffix, op.body); res.Code != http.StatusNotFound {
				t.Errorf("group target: %d, want 404", res.Code)
			}
			if got := te.ph.Requests()[before:]; len(got) != 0 {
				t.Errorf("refused requests reached Pi-hole: %v", got)
			}

			// querylog.view is enough for the reads that need any permission, and for the query log.
			res = viewer.do(op.method, te.path(op.suffix), op.body)
			wantViewer := op.perm == "" || op.perm == rbac.QueryLogView
			if got := res.Code != http.StatusForbidden; got != wantViewer {
				t.Errorf("viewer: %d %s; allowed = %v, want %v", res.Code, res.Body, got, wantViewer)
			}
			if res.Code == http.StatusForbidden {
				if d := errorDetails(t, res); d["permission"] != string(op.perm) || d["target"] != te.target {
					t.Errorf("forbidden details %v", d)
				}
			}
		})
	}

	// Refused writes are audited as permission_denied, with the target.
	res := other.do(http.MethodPut, te.path("/blocking"), gen.BlockingInput{Enabled: false})
	mustStatus(t, res, http.StatusForbidden)
	row, detail := te.lastAudit()
	if row.Action != audit.ActionPermissionDenied || row.Target != te.target || detail["permission"] != "blocking.toggle" {
		t.Errorf("audit %+v %v", row, detail)
	}

	// A disabled instance isn't a target, even for an admin.
	mustStatus(t, te.admin.do(http.MethodPost, instancePath(te.id, "/disable"), nil), http.StatusOK)
	for _, op := range ops {
		if res := te.admin.do(op.method, te.path(op.suffix), op.body); res.Code != http.StatusNotFound {
			t.Errorf("%s %s on a disabled instance: %d, want 404", op.method, op.suffix, res.Code)
		}
	}
}

func TestSummaryAndBlocking(t *testing.T) {
	te := newTargetEnv(t)

	res := te.admin.do(http.MethodGet, te.path("/summary"), nil)
	mustStatus(t, res, http.StatusOK)
	sum := decode[gen.TargetSummary](t, res)
	if sum.Blocking.Blocking != "enabled" || sum.Blocking.Timer != nil || sum.Last24h.Queries != 20000 ||
		sum.Last24h.Clients != 9 || sum.Live.Queries != 1000 || sum.Live.DomainsOnBlocklist != 123456 ||
		sum.Live.Status["GRAVITY"] != 250 || sum.Live.Replies == nil {
		t.Errorf("summary %s", mustJSON(t, sum))
	}

	// Disable for five minutes.
	timer := 300
	res = te.admin.do(http.MethodPut, te.path("/blocking"), gen.BlockingInput{Enabled: false, Timer: &timer})
	mustStatus(t, res, http.StatusOK)
	if st := decode[gen.BlockingStatus](t, res); st.Blocking != "disabled" || st.Timer == nil || *st.Timer != 300 {
		t.Errorf("after disabling: %s", res.Body)
	}
	if on, tm := te.ph.Blocking(); on || tm == nil || *tm != 300 {
		t.Errorf("fake Pi-hole: blocking %v, timer %v", on, tm)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionBlockingSet || row.Result != audit.ResultSuccess || row.Target != te.target ||
		row.InstanceName != "pihole1" || row.InstanceID.Int64 != te.id || detail["enabled"] != false || detail["timer"] != 300.0 {
		t.Errorf("audit %+v %v", row, detail)
	}
	if st := decode[gen.BlockingStatus](t, te.admin.do(http.MethodGet, te.path("/blocking"), nil)); st.Blocking != "disabled" {
		t.Errorf("GET blocking: %+v", st)
	}

	res = te.admin.do(http.MethodPut, te.path("/blocking"), gen.BlockingInput{Enabled: true})
	mustStatus(t, res, http.StatusOK)
	if on, tm := te.ph.Blocking(); !on || tm != nil {
		t.Errorf("fake Pi-hole after enabling: blocking %v, timer %v", on, tm)
	}

	// Bad timers are refused before Pi-hole is asked, and aren't audited.
	n, writes := te.auditCount(), len(te.piholeWrites())
	for _, tt := range []struct {
		enabled bool
		timer   int
	}{{true, 60}, {false, 0}, {false, 86401}, {false, -5}} {
		tm := tt.timer
		res := te.admin.do(http.MethodPut, te.path("/blocking"), gen.BlockingInput{Enabled: tt.enabled, Timer: &tm})
		if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
			t.Errorf("enabled %v timer %d: %d %s", tt.enabled, tt.timer, res.Code, res.Body)
		}
	}
	if te.auditCount() != n || len(te.piholeWrites()) != writes {
		t.Error("an invalid blocking change was audited or sent")
	}
}

func TestRestartDNS(t *testing.T) {
	te := newTargetEnv(t)
	res := te.admin.do(http.MethodPost, te.path("/dns/restart"), nil)
	mustStatus(t, res, http.StatusOK)
	if r := decode[gen.DNSRestartResult](t, res); !r.Confirmed {
		t.Errorf("result %s", res.Body)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionDNSRestart || row.Result != audit.ResultSuccess || detail["confirmed"] != true {
		t.Errorf("audit %+v %v", row, detail)
	}

	// The restart drops the connection: unconfirmed, not an error, and the instance isn't marked down.
	te.ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/action/restartdns" {
			return false
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.(*net.TCPConn).SetLinger(0)
			_ = conn.Close()
		}
		return true
	})
	res = te.admin.do(http.MethodPost, te.path("/dns/restart"), nil)
	mustStatus(t, res, http.StatusOK)
	if r := decode[gen.DNSRestartResult](t, res); r.Confirmed {
		t.Errorf("result %s, want unconfirmed", res.Body)
	}
	if row, detail := te.lastAudit(); row.Action != audit.ActionDNSRestart || row.Result != audit.ResultSuccess || detail["confirmed"] != false {
		t.Errorf("audit %+v %v", row, detail)
	}
	if h, _ := te.srv.Instances.Pool.Health(te.id); h.State != instances.StateUp {
		t.Errorf("health after a dropped restart: %+v", h)
	}
}

func TestDomains(t *testing.T) {
	te := newTargetEnv(t)
	kids := te.ph.AddGroup("kids")
	te.ph.AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Comment: "old", Enabled: false})

	list := decode[gen.DomainList](t, te.admin.do(http.MethodGet, te.path("/domains"), nil))
	if len(list.Domains) != 1 || list.Domains[0].Domain != "games.example" || list.Domains[0].Enabled ||
		!slices.Equal(list.Domains[0].Groups, []int{0}) || list.Domains[0].AddedAt == nil {
		t.Fatalf("list %s", mustJSON(t, list))
	}

	// Add: surrounding spaces go, the Default group is the default.
	res := te.admin.do(http.MethodPost, te.path("/domains"), gen.DomainInput{Domain: "  ads.example ", Type: "deny", Kind: "exact", Comment: strp("tracker")})
	mustStatus(t, res, http.StatusCreated)
	if d := decode[gen.Domain](t, res); d.Domain != "ads.example" || !d.Enabled || !slices.Equal(d.Groups, []int{0}) || d.Comment != "tracker" {
		t.Errorf("added %s", res.Body)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionDomainAdd || row.Result != audit.ResultSuccess || detail["domain"] != "ads.example" ||
		mustJSON(t, detail["groups"]) != `["Default"]` {
		t.Errorf("audit %+v %v", row, detail)
	}

	// A duplicate is Pi-hole's rejection: a 400 with its message, audited as a failure.
	res = te.admin.do(http.MethodPost, te.path("/domains"), gen.DomainInput{Domain: "ads.example", Type: "deny", Kind: "exact"})
	if res.Code != http.StatusBadRequest || res.errorCode() != "pihole_rejected" {
		t.Fatalf("duplicate: %d %s", res.Code, res.Body)
	}
	if d := errorDetails(t, res); d["instance"] != "pihole1" || !strings.Contains(d["pihole_message"].(string), "UNIQUE") {
		t.Errorf("details %v", d)
	}
	if row, detail := te.lastAudit(); row.Action != audit.ActionDomainAdd || row.Result != audit.ResultFailure || detail["error_code"] != "pihole_rejected" {
		t.Errorf("audit %+v %v", row, detail)
	}
	if h, _ := te.srv.Instances.Pool.Health(te.id); h.State != instances.StateUp || h.LastError != "" {
		t.Errorf("health after a rejection: %+v", h)
	}

	// Refused before Pi-hole: bad input and unknown groups. Not audited, nothing written.
	n, writes := te.auditCount(), len(te.piholeWrites())
	for name, in := range map[string]gen.DomainInput{
		"empty":         {Domain: "  ", Type: "deny", Kind: "exact"},
		"bad type":      {Domain: "a.example", Type: "block", Kind: "exact"},
		"bad kind":      {Domain: "a.example", Type: "deny", Kind: "glob"},
		"line break":    {Domain: "a.example\nb", Type: "deny", Kind: "exact"},
		"long exact":    {Domain: strings.Repeat("a", 256), Type: "deny", Kind: "exact"},
		"long comment":  {Domain: "a.example", Type: "deny", Kind: "exact", Comment: strp(strings.Repeat("c", 501))},
		"unknown group": {Domain: "a.example", Type: "deny", Kind: "exact", Groups: intsp(kids, 99)},
		"negative":      {Domain: "a.example", Type: "deny", Kind: "exact", Groups: intsp(-1)},
	} {
		res := te.admin.do(http.MethodPost, te.path("/domains"), in)
		if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}
	if te.auditCount() != n || len(te.piholeWrites()) != writes {
		t.Errorf("refused adds were audited or sent: %v", te.piholeWrites()[writes:])
	}
	// A long regex is fine.
	res = te.admin.do(http.MethodPost, te.path("/domains"), gen.DomainInput{Domain: "^" + strings.Repeat("a", 500) + "$", Type: "deny", Kind: "regex", Groups: intsp()})
	mustStatus(t, res, http.StatusCreated)
	if d := decode[gen.Domain](t, res); len(d.Groups) != 0 {
		t.Errorf("an empty groups list gave %v", d.Groups)
	}

	// Update: groups and comment change, the entry stays disabled.
	res = te.admin.do(http.MethodPatch, te.path("/domains"), gen.DomainUpdate{Domain: "games.example", Type: "deny", Kind: "exact", Groups: intsp(kids, kids, 0)})
	mustStatus(t, res, http.StatusOK)
	if d := decode[gen.Domain](t, res); d.Enabled || !slices.Equal(d.Groups, []int{0, kids}) || d.Comment != "old" {
		t.Errorf("updated %s", res.Body)
	}
	got := te.ph.Domains()[0]
	if got.Enabled || !slices.Equal(got.Groups, []int{0, kids}) || got.Comment != "old" {
		t.Errorf("fake Pi-hole after update: %+v", got)
	}
	row, detail = te.lastAudit()
	if row.Action != audit.ActionDomainUpdate || mustJSON(t, detail["groups_before"]) != `["Default"]` ||
		mustJSON(t, detail["groups_after"]) != `["Default","kids"]` || detail["comment_changed"] != false {
		t.Errorf("audit %+v %v", row, detail)
	}

	// A change that changes nothing isn't sent or audited.
	n, writes = te.auditCount(), len(te.piholeWrites())
	res = te.admin.do(http.MethodPatch, te.path("/domains"), gen.DomainUpdate{Domain: "games.example", Type: "deny", Kind: "exact", Comment: strp("old")})
	mustStatus(t, res, http.StatusOK)
	if te.auditCount() != n || len(te.piholeWrites()) != writes {
		t.Error("a no-op update was audited or sent")
	}

	// An entry that doesn't exist is a 404, and is never created: the same domain on the allow list isn't it.
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		var body any = gen.DomainKey{Domain: "games.example", Type: "allow", Kind: "exact"}
		if method == http.MethodPatch {
			body = gen.DomainUpdate{Domain: "games.example", Type: "allow", Kind: "exact", Comment: strp("x")}
		}
		res := te.admin.do(method, te.path("/domains"), body)
		if res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
			t.Errorf("%s of a missing entry: %d %s", method, res.Code, res.Body)
		}
	}
	if te.auditCount() != n || len(te.piholeWrites()) != writes || len(te.ph.Domains()) != 3 {
		t.Errorf("a missing entry was written: %v", te.piholeWrites()[writes:])
	}
	if res := te.admin.do(http.MethodPatch, te.path("/domains"), gen.DomainUpdate{Domain: "games.example", Type: "deny", Kind: "exact"}); res.Code != http.StatusBadRequest {
		t.Errorf("update with nothing to change: %d", res.Code)
	}

	// Delete.
	res = te.admin.do(http.MethodDelete, te.path("/domains"), gen.DomainKey{Domain: "games.example", Type: "deny", Kind: "exact"})
	mustStatus(t, res, http.StatusNoContent)
	if slices.ContainsFunc(te.ph.Domains(), func(d piholetest.Domain) bool { return d.Domain == "games.example" }) {
		t.Error("the entry is still there")
	}
	row, detail = te.lastAudit()
	if row.Action != audit.ActionDomainDelete || row.Result != audit.ResultSuccess || detail["comment"] != "old" ||
		mustJSON(t, detail["groups"]) != `["Default","kids"]` || detail["enabled"] != false {
		t.Errorf("audit %+v %v", row, detail)
	}
}

func TestClients(t *testing.T) {
	te := newTargetEnv(t)
	lab := te.ph.AddGroup("lab")
	te.ph.AddClient(piholetest.Client{Client: "10.0.0.0/24", Name: "", Comment: "lab subnet"})
	te.ph.AddClient(piholetest.Client{Client: "10.0.1.5", Name: "printer.lan"})

	list := decode[gen.ClientList](t, te.admin.do(http.MethodGet, te.path("/clients"), nil))
	if len(list.Clients) != 2 || list.Clients[0].Name != nil || list.Clients[1].Name == nil || *list.Clients[1].Name != "printer.lan" {
		t.Fatalf("list %s", mustJSON(t, list))
	}

	res := te.admin.do(http.MethodPatch, te.path("/clients"), gen.ClientUpdate{Client: "10.0.0.0/24", Groups: intsp(lab)})
	mustStatus(t, res, http.StatusOK)
	if c := decode[gen.PiholeClient](t, res); !slices.Equal(c.Groups, []int{lab}) || c.Comment != "lab subnet" {
		t.Errorf("updated %s", res.Body)
	}
	if got := te.ph.Clients()[0]; !slices.Equal(got.Groups, []int{lab}) || got.Comment != "lab subnet" {
		t.Errorf("fake Pi-hole: %+v", got)
	}
	if !slices.Contains(te.ph.Requests(), "PUT /api/clients/10.0.0.0%2F24") {
		t.Errorf("requests %v", te.ph.Requests())
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionClientUpdate || detail["client"] != "10.0.0.0/24" ||
		mustJSON(t, detail["groups_before"]) != `["Default"]` || mustJSON(t, detail["groups_after"]) != `["lab"]` {
		t.Errorf("audit %+v %v", row, detail)
	}

	// A client that doesn't exist is never created: clients.edit can't add clients.
	writes := len(te.piholeWrites())
	res = te.admin.do(http.MethodPatch, te.path("/clients"), gen.ClientUpdate{Client: "10.0.0.99", Comment: strp("sneaky")})
	if res.Code != http.StatusNotFound {
		t.Errorf("missing client: %d %s", res.Code, res.Body)
	}
	if len(te.piholeWrites()) != writes || len(te.ph.Clients()) != 2 {
		t.Errorf("a missing client was written: %v", te.piholeWrites()[writes:])
	}
	for name, in := range map[string]gen.ClientUpdate{
		"empty":         {Client: "", Comment: strp("x")},
		"nothing":       {Client: "10.0.1.5"},
		"control":       {Client: "10.0.1.5", Comment: strp("a\tb")},
		"unknown group": {Client: "10.0.1.5", Groups: intsp(42)},
	} {
		if res := te.admin.do(http.MethodPatch, te.path("/clients"), in); res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, res.Code, res.Body)
		}
	}

	groups := decode[gen.PiholeGroupList](t, te.admin.do(http.MethodGet, te.path("/groups"), nil))
	if len(groups.Groups) != 2 || groups.Groups[0].Name != "Default" || groups.Groups[1].Id != lab {
		t.Errorf("groups %s", mustJSON(t, groups))
	}
}

func TestQueries(t *testing.T) {
	te := newTargetEnv(t)
	var qs []piholetest.Query
	for i, d := range []string{"ads.example", "news.example", "ADS.other", "mail.example"} {
		var q piholetest.Query
		q.ID, q.Time, q.Type, q.Domain, q.Status = i, 1790000000.25-float64(i), "A", d, "FORWARDED"
		q.Client.IP, q.Client.Name = "10.0.0."+strconv.Itoa(i+1), map[bool]string{true: "laptop.lan"}[i == 1]
		q.Reply.Type, q.Reply.Time = "IP", 0.5
		qs = append(qs, q)
	}
	te.ph.SetQueries(qs)

	get := func(query string) gen.QueryLog {
		t.Helper()
		res := te.admin.do(http.MethodGet, te.path("/queries"+query), nil)
		mustStatus(t, res, http.StatusOK)
		return decode[gen.QueryLog](t, res)
	}
	all := get("")
	if len(all.Queries) != 4 {
		t.Fatalf("got %d entries", len(all.Queries))
	}
	q := all.Queries[0]
	if q.Domain != "ads.example" || q.Time.UnixMilli() != 1790000000250 || q.ClientName != nil ||
		q.ReplyTimeMs == nil || *q.ReplyTimeMs != 500 || q.Upstream != nil {
		t.Errorf("first entry %s", mustJSON(t, q))
	}
	if n := all.Queries[1].ClientName; n == nil || *n != "laptop.lan" {
		t.Errorf("client name %v", n)
	}
	if got := get("?domain=ads"); len(got.Queries) != 2 {
		t.Errorf("domain filter: %d entries, want 2 (case-insensitive)", len(got.Queries))
	}
	if got := get("?client=laptop"); len(got.Queries) != 1 {
		t.Errorf("client name filter: %d entries", len(got.Queries))
	}
	if got := get("?length=2&domain=ads"); len(got.Queries) != 1 {
		t.Errorf("filters apply to the entries read: %d entries, want 1", len(got.Queries))
	}
	if !slices.Contains(te.ph.Requests(), "GET /api/queries") {
		t.Errorf("requests %v", te.ph.Requests())
	}
	for _, bad := range []string{"?length=0", "?length=1001", "?length=abc", "?domain=" + strings.Repeat("a", 256)} {
		if res := te.admin.do(http.MethodGet, te.path("/queries"+bad), nil); res.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, res.Code)
		}
	}
}

// TestPiholeFailures: a Pi-hole that is down is a 502 naming the instance, without the underlying error, which can
// name internal addresses.
func TestPiholeFailures(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.Close()
	res := te.admin.do(http.MethodGet, te.path("/domains"), nil)
	if res.Code != http.StatusBadGateway || res.errorCode() != "pihole_unreachable" {
		t.Fatalf("down: %d %s", res.Code, res.Body)
	}
	d := errorDetails(t, res)
	if d["instance"] != "pihole1" || d["detail"] != nil || strings.Contains(res.Body.String(), "127.0.0.1") {
		t.Errorf("details %v", d)
	}
	// Within the backoff, a write fails at once and isn't audited: it was never sent.
	n := te.auditCount()
	res = te.admin.do(http.MethodPut, te.path("/blocking"), gen.BlockingInput{Enabled: false})
	if res.Code != http.StatusBadGateway {
		t.Errorf("write while down: %d", res.Code)
	}
	if te.auditCount() != n {
		t.Error("a write that was never sent was audited")
	}
}

func TestPiholeFailedStatuses(t *testing.T) {
	e := newTestEnv(t)
	tests := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{&piholeapi.RejectedError{Message: "Invalid domain"}, http.StatusBadRequest, piholeapi.CodeRejected},
		{piholeapi.ErrUnreachable, http.StatusBadGateway, piholeapi.CodeUnreachable},
		{piholeapi.ErrAuthRejected, http.StatusBadGateway, piholeapi.CodeAuthRejected},
		{&piholeapi.StatusError{Code: 500}, http.StatusBadGateway, piholeapi.CodeStatusError},
		{instances.ErrNoPassword, http.StatusConflict, instances.CodePasswordMissing},
		{instances.ErrMisconfigured, http.StatusConflict, instances.CodeMisconfigured},
	}
	for _, tt := range tests {
		t.Run(tt.wantCode, func(t *testing.T) {
			w := httptest.NewRecorder()
			e.srv.piholeFailed(w, httptest.NewRequest(http.MethodGet, "/", nil), &piholeFailure{Instance: "pihole1", Err: tt.err})
			res := response{w}
			if res.Code != tt.wantStatus || res.errorCode() != tt.wantCode {
				t.Errorf("status %d code %q, want %d %q", res.Code, res.errorCode(), tt.wantStatus, tt.wantCode)
			}
			if d := errorDetails(t, res); d["instance"] != "pihole1" {
				t.Errorf("details %v", d)
			}
		})
	}
}
