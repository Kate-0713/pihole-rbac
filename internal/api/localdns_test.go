// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// TestMain shortens the wait after a CNAME change: the fake Pi-holes restart at once, so the two seconds a real one
// must keep answering would only slow the tests down.
func TestMain(m *testing.M) {
	restore := piholeapi.SetRestartTiming(10*time.Millisecond, 20*time.Millisecond)
	code := m.Run()
	restore()
	os.Exit(code)
}

func reason(s string) *gen.LocalDNSReasonText { return &s }

// newDNSEnv is newTargetEnv with the fake's app_sudo on and restarts that don't drop connections, so CNAME writes
// needn't wait for the fake to come back.
func newDNSEnv(t *testing.T, modify ...func(*Options)) *targetEnv {
	te := newTargetEnv(t, modify...)
	te.ph.SetAppSudo(true)
	te.ph.SetRestartOutage(0)
	return te
}

func TestLocalDNSReads(t *testing.T) {
	te := newDNSEnv(t)
	mustStatus(t, te.admin.do(http.MethodPost, te.path("/local-dns/records"),
		gen.DNSRecordInput{Ip: "10.0.0.7", Hostname: "tv.lab", Reason: reason("living room")}), http.StatusOK)
	// Set afterwards: FTL checks the whole array on every add, so an entry it doesn't accept (here "garbage", which
	// could only come from a hand-edited pihole.toml) makes every add fail.
	te.ph.SetLocalDNS(
		[]string{"10.0.0.5 nas.lab", "10.0.0.6 printer.lab printer # office", "fd00::5 nas.lab", "garbage", "10.0.0.7 tv.lab"},
		[]string{"alias.lab,nas.lab,300", "a.lab,b.lab,nas.lab"},
	)

	out := decode[gen.LocalDNS](t, te.admin.do(http.MethodGet, te.path("/local-dns"), nil))
	type row struct{ key, marks, reason string }
	var records []row
	for _, r := range out.Records {
		var marks []string
		for _, m := range r.Marks {
			marks = append(marks, string(m))
		}
		rs := ""
		if r.Reason != nil {
			rs = r.Reason.Reason + " by " + r.Reason.By
		}
		records = append(records, row{r.Key, strings.Join(marks, ","), rs})
	}
	want := []row{
		{"10.0.0.5 nas.lab", "", ""},
		{"10.0.0.6 printer.lab printer", "multiple_names,comment", ""},
		{"fd00::5 nas.lab", "", ""},
		{"garbage", "unparsed", ""},
		{"10.0.0.7 tv.lab", "", "living room by admin"},
	}
	if !slices.Equal(records, want) {
		t.Errorf("records %v, want %v", records, want)
	}
	if r := out.Records[1]; r.Comment == nil || *r.Comment != "office" || r.Value != "10.0.0.6 printer.lab printer # office" {
		t.Errorf("record with a comment %+v", r)
	}
	if r := out.Records[3]; r.Ip != nil || len(r.Hostnames) != 0 {
		t.Errorf("unparsed record %+v", r)
	}
	if c := out.Cnames[0]; c.Key != "alias.lab,nas.lab,300" || c.Ttl == nil || *c.Ttl != 300 || c.Target == nil || *c.Target != "nas.lab" {
		t.Errorf("cname %+v", c)
	}
	if c := out.Cnames[1]; len(c.Aliases) != 2 || len(c.Marks) != 1 || c.Marks[0] != "multiple_names" {
		t.Errorf("cname with two aliases %+v", c)
	}
	if len(out.Instances) != 1 || out.Instances[0].Writable != "ok" || out.Members != nil || out.Drifted != nil || !out.ReasonRequired {
		t.Errorf("instances %+v", out.Instances)
	}

	for _, c := range []struct {
		setup  func()
		want   string
		locked bool
	}{
		{func() { te.ph.SetAppSudo(false) }, "app_sudo_off", false},
		{func() { te.ph.SetAppSudo(true); te.ph.SetConfigReadOnly(true) }, "locked", false},
		{func() { te.ph.SetConfigReadOnly(false); te.ph.LockLocalDNS(true, false) }, "ok", true},
	} {
		c.setup()
		in := decode[gen.LocalDNS](t, te.admin.do(http.MethodGet, te.path("/local-dns"), nil)).Instances[0]
		if string(in.Writable) != c.want || in.RecordsLocked != c.locked || in.CnamesLocked {
			t.Errorf("instance %+v, want %s locked %v", in, c.want, c.locked)
		}
	}
}

// TestLocalDNSWrites covers writes to one instance: what is sent, what is refused before anything is, and the audit
// rows, including the reasons the reads show.
func TestLocalDNSWrites(t *testing.T) {
	var svc *loginsettings.Service
	te := newDNSEnv(t, withLoginSettings(t, &svc))
	te.ph.SetLocalDNS([]string{"10.0.0.5 nas.lab", "10.0.0.5  NAS.lab", "10.0.0.6\tPrinter.lab"}, []string{"Alias.lab, nas.lab"})
	records, cnames := te.path("/local-dns/records"), te.path("/local-dns/cnames")
	writesSince := func(n int) []string { return te.piholeWrites()[n:] }

	t.Run("add a record", func(t *testing.T) {
		n := len(te.piholeWrites())
		res := te.admin.do(http.MethodPost, records, gen.DNSRecordInput{Ip: " 10.0.0.7 ", Hostname: "TV.lab", Reason: reason(" new TV ")})
		mustStatus(t, res, http.StatusOK)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"pihole1:ok"}) {
			t.Errorf("results %v", got)
		}
		if w := writesSince(n); !slices.Equal(w, []string{"PUT /api/config/dns/hosts/10.0.0.7%20tv.lab"}) {
			t.Errorf("sent %v", w)
		}
		row, d := te.lastAudit()
		if row.Action != audit.ActionDNSRecordAdd || d["key"] != "10.0.0.7 tv.lab" || d["reason"] != "new TV" || d["directory_domain"] != nil {
			t.Errorf("audit %s %v", row.Action, d)
		}
	})

	refused := []struct {
		name, path string
		body       any
		code       string
		field      string
	}{
		{"a duplicate by key", records, gen.DNSRecordInput{Ip: "10.0.0.6", Hostname: "printer.lab", Reason: reason("x")}, "conflict", ""},
		{"a bad hostname", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "bad name", Reason: reason("x")}, "validation_failed", "hostname"},
		{"an injected line", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "a.lab\n10.0.0.9 evil", Reason: reason("x")}, "validation_failed", "hostname"},
		{"a bad address", records, gen.DNSRecordInput{Ip: "10.0.0.256", Hostname: "a.lab", Reason: reason("x")}, "validation_failed", "ip"},
		{"no reason", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "a.lab"}, "validation_failed", "reason"},
		{"a blank reason", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "a.lab", Reason: reason("   ")}, "validation_failed", "reason"},
		{"a long reason", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "a.lab", Reason: reason(strings.Repeat("x", 201))}, "validation_failed", "reason"},
		{"a reason with a line break", records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "a.lab", Reason: reason("a\nb")}, "validation_failed", "reason"},
		{"a CNAME with a comma", cnames, gen.CNAMEInput{Alias: "a.lab,b.lab", Target: "nas.lab", Reason: reason("x")}, "validation_failed", "alias"},
		{"a CNAME to itself", cnames, gen.CNAMEInput{Alias: "a.lab", Target: "A.lab", Reason: reason("x")}, "validation_failed", "target"},
		{"a duplicate CNAME", cnames, gen.CNAMEInput{Alias: "ALIAS.lab", Target: "nas.lab", Reason: reason("x")}, "conflict", ""},
		{"a change from a missing record", records, gen.DNSRecordUpdate{From: gen.DNSRecordRef{Ip: strp("10.0.0.9"), Hostname: strp("x.lab")}, To: gen.DNSRecordFields{Ip: "10.0.0.9", Hostname: "y.lab"}, Reason: reason("x")}, "not_found", ""},
		{"a ref by value and fields", records, gen.DNSRecordDelete{Record: gen.DNSRecordRef{Value: strp("10.0.0.5 nas.lab"), Ip: strp("10.0.0.5")}, Reason: reason("x")}, "validation_failed", "record"},
		{"a ref with neither", records, gen.DNSRecordDelete{Record: gen.DNSRecordRef{Ip: strp("10.0.0.5")}, Reason: reason("x")}, "validation_failed", "record"},
		{"a delete of a missing CNAME", cnames, gen.CNAMEDelete{Cname: gen.CNAMERef{Value: strp("x.lab,nas.lab")}, Reason: reason("x")}, "not_found", ""},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			n, audits := len(te.piholeWrites()), te.auditCount()
			method := http.MethodPost
			switch c.body.(type) {
			case gen.DNSRecordUpdate:
				method = http.MethodPatch
			case gen.DNSRecordDelete, gen.CNAMEDelete:
				method = http.MethodDelete
			}
			res := te.admin.do(method, c.path, c.body)
			if res.errorCode() != c.code {
				t.Fatalf("%d %s, want %s", res.Code, res.Body, c.code)
			}
			if c.field != "" && errorDetails(t, res)["field"] != c.field {
				t.Errorf("field %v, want %s", errorDetails(t, res)["field"], c.field)
			}
			if w := writesSince(n); len(w) != 0 {
				t.Errorf("sent %v", w)
			}
			if te.auditCount() != audits {
				t.Error("a refused change was audited")
			}
		})
	}

	settings := func(change func(*gen.GeneralSettingsInput)) {
		t.Helper()
		g := svc.General()
		in := gen.GeneralSettingsInput{SessionLifetimeMinutes: g.SessionLifetimeMinutes, IdleTimeoutMinutes: g.IdleTimeoutMinutes}
		change(&in)
		mustStatus(t, te.admin.do(http.MethodPut, "/api/v1/settings/general", in), http.StatusOK)
	}

	t.Run("reasons can be made optional", func(t *testing.T) {
		settings(func(in *gen.GeneralSettingsInput) { in.LocaldnsReasonRequired = new(bool) })
		t.Cleanup(func() { settings(func(in *gen.GeneralSettingsInput) { in.LocaldnsReasonRequired = ptrTrue() }) })
		mustStatus(t, te.admin.do(http.MethodPost, records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "quiet.lab"}), http.StatusOK)
		if _, d := te.lastAudit(); d["reason"] != "" {
			t.Errorf("audit %v", d)
		}
		res := te.admin.do(http.MethodPost, records, gen.DNSRecordInput{Ip: "10.0.0.8", Hostname: "loud.lab", Reason: reason(strings.Repeat("x", 201))})
		if res.errorCode() != "validation_failed" {
			t.Errorf("a long optional reason: %d", res.Code)
		}
	})

	t.Run("a name under a directory domain", func(t *testing.T) {
		settings(func(in *gen.GeneralSettingsInput) { in.LocaldnsExtraDomains = &[]string{"corp.example"} })
		n := len(te.piholeWrites())
		body := gen.CNAMEInput{Alias: "intranet.Corp.example", Target: "nas.lab", Reason: reason("x")}
		res := te.admin.do(http.MethodPost, cnames, body)
		if res.errorCode() != "confirmation_required" || errorDetails(t, res)["domain"] != "corp.example" || errorDetails(t, res)["field"] != "alias" {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		if w := writesSince(n); len(w) != 0 {
			t.Errorf("sent %v", w)
		}
		mustStatus(t, te.admin.do(http.MethodPost, cnames+"?confirm=true", body), http.StatusOK)
		if _, d := te.lastAudit(); d["directory_domain"] != true {
			t.Errorf("audit %v", d)
		}
		// A target under the domain is what a CNAME is for, so it isn't checked.
		mustStatus(t, te.admin.do(http.MethodPost, cnames, gen.CNAMEInput{Alias: "wiki.lab", Target: "wiki.corp.example", Reason: reason("x")}), http.StatusOK)
	})

	t.Run("change a record", func(t *testing.T) {
		n, restarts := len(te.piholeWrites()), te.ph.Restarts()
		res := te.admin.do(http.MethodPatch, records, gen.DNSRecordUpdate{
			From: gen.DNSRecordRef{Ip: strp("10.0.0.7"), Hostname: strp("tv.lab")}, To: gen.DNSRecordFields{Ip: "10.0.0.17", Hostname: "tv.lab"}, Reason: reason("moved"),
		})
		mustStatus(t, res, http.StatusOK)
		if w := writesSince(n); !slices.Equal(w, []string{"PUT /api/config/dns/hosts/10.0.0.17%20tv.lab", "DELETE /api/config/dns/hosts/10.0.0.7%20tv.lab"}) {
			t.Errorf("sent %v", w)
		}
		if te.ph.Restarts() != restarts {
			t.Error("a host record change restarted FTL")
		}
		row, d := te.lastAudit()
		if row.Action != audit.ActionDNSRecordUpdate || d["key"] != "10.0.0.17 tv.lab" || d["key_before"] != "10.0.0.7 tv.lab" || d["reason"] != "moved" {
			t.Errorf("audit %s %v", row.Action, d)
		}
		out := decode[gen.LocalDNS](t, te.admin.do(http.MethodGet, te.path("/local-dns"), nil))
		i := slices.IndexFunc(out.Records, func(r gen.DNSRecord) bool { return r.Key == "10.0.0.17 tv.lab" })
		if i < 0 || out.Records[i].Reason == nil || out.Records[i].Reason.Reason != "moved" {
			t.Errorf("the changed record's reason: %+v", out.Records)
		}
	})

	t.Run("a change to the same key sends nothing", func(t *testing.T) {
		n, audits := len(te.piholeWrites()), te.auditCount()
		mustStatus(t, te.admin.do(http.MethodPatch, records, gen.DNSRecordUpdate{
			From: gen.DNSRecordRef{Value: strp("10.0.0.17 tv.lab")}, To: gen.DNSRecordFields{Ip: "10.0.0.17", Hostname: "TV.lab"}, Reason: reason("x"),
		}), http.StatusOK)
		if len(writesSince(n)) != 0 || te.auditCount() != audits {
			t.Error("a change that changes nothing was sent or audited")
		}
	})

	t.Run("a delete removes every spelling", func(t *testing.T) {
		n := len(te.piholeWrites())
		mustStatus(t, te.admin.do(http.MethodDelete, records, gen.DNSRecordDelete{Record: gen.DNSRecordRef{Ip: strp("10.0.0.5"), Hostname: strp("nas.lab")}, Reason: reason("gone")}), http.StatusOK)
		if w := writesSince(n); !slices.Equal(w, []string{"DELETE /api/config/dns/hosts/10.0.0.5%20nas.lab", "DELETE /api/config/dns/hosts/10.0.0.5%20%20NAS.lab"}) {
			t.Errorf("sent %v", w)
		}
		if row, d := te.lastAudit(); row.Action != audit.ActionDNSRecordDelete || len(d["values"].([]any)) != 2 || d["reason"] != "gone" {
			t.Errorf("audit %s %v", row.Action, d)
		}
	})

	t.Run("CNAMEs restart FTL once per change", func(t *testing.T) {
		restarts := te.ph.Restarts()
		mustStatus(t, te.admin.do(http.MethodPost, cnames, gen.CNAMEInput{Alias: "tv2.lab", Target: "tv.lab", Ttl: new(int), Reason: reason("x")}), http.StatusOK)
		res := te.admin.do(http.MethodPatch, cnames, gen.CNAMEUpdate{
			From: gen.CNAMERef{Alias: strp("tv2.lab"), Target: strp("tv.lab"), Ttl: new(int)}, To: gen.CNAMEFields{Alias: "tv3.lab", Target: "tv.lab"}, Reason: reason("x"),
		})
		mustStatus(t, res, http.StatusOK)
		if r := results(t, res); len(r) != 1 {
			t.Errorf("results %v", r)
		}
		mustStatus(t, te.admin.do(http.MethodDelete, cnames, gen.CNAMEDelete{Cname: gen.CNAMERef{Value: strp("tv3.lab,tv.lab")}, Reason: reason("x")}), http.StatusOK)
		if got := te.ph.Restarts() - restarts; got != 3 {
			t.Errorf("%d restarts for an add, a change and a delete, want 3", got)
		}
		_, cn := te.ph.LocalDNS()
		if slices.ContainsFunc(cn, func(v string) bool { return strings.HasPrefix(v, "tv") }) {
			t.Errorf("cnames %q", cn)
		}
	})

	t.Run("app_sudo off", func(t *testing.T) {
		te.ph.SetAppSudo(false)
		t.Cleanup(func() { te.ph.SetAppSudo(true) })
		res := te.admin.do(http.MethodPost, records, gen.DNSRecordInput{Ip: "10.0.0.9", Hostname: "x.lab", Reason: reason("x")})
		if res.Code != http.StatusConflict || res.errorCode() != "pihole_app_sudo_off" || !strings.Contains(res.Body.String(), "pihole-FTL --config webserver.api.app_sudo true") {
			t.Errorf("%d %s", res.Code, res.Body)
		}
		if row, d := te.lastAudit(); row.Action != audit.ActionDNSRecordAdd || row.Result != audit.ResultFailure || d["error_code"] != "pihole_app_sudo_off" {
			t.Errorf("audit %s %s %v", row.Action, row.Result, d)
		}
	})
}

// TestLocalDNSPartialChange: a change whose delete fails keeps the new record, says so, and still shows its reason.
func TestLocalDNSPartialChange(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetLocalDNS([]string{"10.0.0.5 nas.lab"}, []string{"alias.lab,nas.lab"})
	te.ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/config/") {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		return false
	})
	restarts := te.ph.Restarts()
	res := te.admin.do(http.MethodPatch, te.path("/local-dns/cnames"), gen.CNAMEUpdate{
		From: gen.CNAMERef{Value: strp("alias.lab,nas.lab")}, To: gen.CNAMEFields{Alias: "alias2.lab", Target: "nas.lab"}, Reason: reason("rename"),
	})
	if res.Code != http.StatusBadGateway {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if !strings.Contains(res.Body.String(), `"added":true`) {
		t.Errorf("the answer doesn't say the new CNAME was added: %s", res.Body)
	}
	_, cn := te.ph.LocalDNS()
	if !slices.Equal(cn, []string{"alias.lab,nas.lab", "alias2.lab,nas.lab"}) {
		t.Errorf("cnames %q", cn)
	}
	if te.ph.Restarts() != restarts+1 {
		t.Errorf("FTL wasn't restarted to serve the new CNAME (%d restarts)", te.ph.Restarts()-restarts)
	}
	if _, d := te.lastAudit(); d["added"] != true {
		t.Errorf("audit %v", d)
	}
	te.ph.Handle(nil)
	out := decode[gen.LocalDNS](t, te.admin.do(http.MethodGet, te.path("/local-dns"), nil))
	if c := out.Cnames[1]; c.Key != "alias2.lab,nas.lab" || c.Reason == nil || c.Reason.Reason != "rename" {
		t.Errorf("the new CNAME %+v", c)
	}
}

// TestLocalDNSRestartWait: a CNAME write answers once the Pi-hole is back after restarting.
func TestLocalDNSRestartWait(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetRestartOutage(2)
	res := te.admin.do(http.MethodPost, te.path("/local-dns/cnames"), gen.CNAMEInput{Alias: "a.lab", Target: "b.lab", Reason: reason("x")})
	mustStatus(t, res, http.StatusOK)
	if strings.Contains(res.Body.String(), "restart_pending") {
		t.Errorf("answer %s", res.Body)
	}
	mustStatus(t, te.admin.do(http.MethodGet, te.path("/local-dns"), nil), http.StatusOK)
}

func TestLocalDNSPermissions(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetLocalDNS([]string{"10.0.0.5 nas.lab"}, nil)
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.LocalDNSView, "instance", te.id))
	te.addGrantUser("editor", "editor-password-1", grant(rbac.LocalDNSEdit, "instance", te.id))
	te.addGrantUser("lists", "lists-password-1", grant(rbac.ListsEdit, "instance", te.id), grant(rbac.ListsView, "instance", te.id))
	viewer := te.loggedIn("viewer", "viewer-password-1")
	editor := te.loggedIn("editor", "editor-password-1")
	lists := te.loggedIn("lists", "lists-password-1")

	mustStatus(t, viewer.do(http.MethodGet, te.path("/local-dns"), nil), http.StatusOK)
	for _, c := range []struct {
		who          *client
		method, path string
		body         any
		perm         rbac.Permission
	}{
		{editor, http.MethodGet, "/local-dns", nil, rbac.LocalDNSView},
		{lists, http.MethodGet, "/local-dns", nil, rbac.LocalDNSView},
		{viewer, http.MethodPost, "/local-dns/records", gen.DNSRecordInput{Ip: "10.0.0.6", Hostname: "a.lab", Reason: reason("x")}, rbac.LocalDNSEdit},
		{viewer, http.MethodPost, "/local-dns/cnames", gen.CNAMEInput{Alias: "a.lab", Target: "b.lab", Reason: reason("x")}, rbac.LocalDNSEdit},
		{lists, http.MethodDelete, "/local-dns/records", gen.DNSRecordDelete{Record: gen.DNSRecordRef{Value: strp("10.0.0.5 nas.lab")}, Reason: reason("x")}, rbac.LocalDNSEdit},
	} {
		res := c.who.do(c.method, te.path(c.path), c.body)
		if res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != string(c.perm) {
			t.Errorf("%s %s: %d %s, want 403 for %s", c.method, c.path, res.Code, res.Body, c.perm)
		}
	}
	if w := te.piholeWrites(); len(w) != 0 {
		t.Errorf("writes %v", w)
	}
	mustStatus(t, editor.do(http.MethodPost, te.path("/local-dns/records"), gen.DNSRecordInput{Ip: "10.0.0.6", Hostname: "a.lab", Reason: reason("x")}), http.StatusOK)
}

func TestLocalDNSSettings(t *testing.T) {
	te := newDNSEnv(t, withLoginSettings(t, nil))
	got := decode[gen.GeneralSettings](t, te.admin.do(http.MethodGet, "/api/v1/settings/general", nil))
	if !got.LocaldnsReasonRequired || got.LocaldnsExtraDomains == nil || len(got.LocaldnsExtraDomains) != 0 {
		t.Errorf("defaults %+v", got)
	}
	put := func(body gen.GeneralSettingsInput) response {
		return te.admin.do(http.MethodPut, "/api/v1/settings/general", body)
	}
	base := gen.GeneralSettingsInput{SessionLifetimeMinutes: got.SessionLifetimeMinutes, IdleTimeoutMinutes: got.IdleTimeoutMinutes}
	in := base
	in.LocaldnsReasonRequired = new(bool)
	in.LocaldnsExtraDomains = &[]string{"Home.arpa", "lab", "home.arpa"}
	res := put(in)
	mustStatus(t, res, http.StatusOK)
	got = decode[gen.GeneralSettings](t, res)
	if got.LocaldnsReasonRequired || !slices.Equal(got.LocaldnsExtraDomains, []string{"home.arpa", "lab"}) {
		t.Errorf("saved %+v", got)
	}
	row, d := te.lastAudit()
	if row.Action != audit.ActionSettingsUpdate || !slices.Equal(anyStrings(d["changed"]), []string{"localdns_reason_required", "localdns_extra_domains"}) {
		t.Errorf("audit %s %v", row.Action, d)
	}
	// Left out, they are kept.
	got = decode[gen.GeneralSettings](t, put(base))
	if got.LocaldnsReasonRequired || len(got.LocaldnsExtraDomains) != 2 {
		t.Errorf("after a save without them %+v", got)
	}
	bad := base
	bad.LocaldnsExtraDomains = &[]string{"ok.lab", "not a domain"}
	if res := put(bad); res.errorCode() != "validation_failed" || errorDetails(t, res)["field"] != "localdns_extra_domains" {
		t.Errorf("a bad domain: %d %s", res.Code, res.Body)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestInstanceTestReportsAppSudo(t *testing.T) {
	te := newTargetEnv(t)
	test := func() gen.InstanceTestResult {
		return decode[gen.InstanceTestResult](t, te.admin.do(http.MethodPost, instancePath(te.id, "/test"), nil))
	}
	if r := test(); !r.Ok || r.AppSudo == nil || *r.AppSudo {
		t.Errorf("app_sudo off: %+v", r)
	}
	te.ph.SetAppSudo(true)
	if r := test(); !r.Ok || r.AppSudo == nil || !*r.AppSudo {
		t.Errorf("app_sudo on: %+v", r)
	}
}

// TestGroupLocalDNS covers a mirrored group: host records fan out, CNAMEs go one member at a time and stop at a
// failure, drift compares keys, and reconcile copies only what the app could have written.
func TestGroupLocalDNS(t *testing.T) {
	ge := newGroupEnv(t)
	d := ge.withDrift()
	for _, ph := range ge.ph {
		ph.SetAppSudo(true)
		ph.SetRestartOutage(0)
	}
	records, cnames := ge.path("/local-dns/records"), ge.path("/local-dns/cnames")

	// gamma already has the record, spelled differently.
	ge.ph["gamma"].SetLocalDNS([]string{"10.0.0.5  NAS.lab"}, nil)
	res := ge.admin.do(http.MethodPost, records, gen.DNSRecordInput{Ip: "10.0.0.5", Hostname: "nas.lab", Reason: reason("x")})
	mustStatus(t, res, http.StatusOK)
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:ok", "gamma:ok"}) {
		t.Errorf("results %v", got)
	}
	if !strings.Contains(res.Body.String(), `"already_present":true`) {
		t.Errorf("gamma isn't reported as already having it: %s", res.Body)
	}
	if h, _ := ge.ph["gamma"].LocalDNS(); !slices.Equal(h, []string{"10.0.0.5  NAS.lab"}) {
		t.Errorf("gamma's records %q", h)
	}
	if rows, ds := ge.auditSince(0); len(rows) == 0 || ds[len(ds)-1]["via"] != ge.target {
		t.Errorf("audit %v", ds)
	}

	t.Run("CNAMEs one member at a time", func(t *testing.T) {
		res := ge.admin.do(http.MethodPost, cnames, gen.CNAMEInput{Alias: "files.lab", Target: "nas.lab", Reason: reason("x")})
		mustStatus(t, res, http.StatusOK)
		for name, ph := range ge.ph {
			if ph.Restarts() != 1 {
				t.Errorf("%s restarted %d times", name, ph.Restarts())
			}
		}
	})

	t.Run("a failing member stops the rest", func(t *testing.T) {
		ge.ph["beta"].SetAppSudo(false)
		t.Cleanup(func() { ge.ph["beta"].SetAppSudo(true) })
		res := ge.admin.do(http.MethodPost, cnames, gen.CNAMEInput{Alias: "media.lab", Target: "nas.lab", Reason: reason("x")})
		mustStatus(t, res, http.StatusMultiStatus)
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:failed:pihole_app_sudo_off", "gamma:skipped:stopped"}) {
			t.Errorf("results %v", got)
		}
		if _, cn := ge.ph["gamma"].LocalDNS(); slices.Contains(cn, "media.lab,nas.lab") {
			t.Error("gamma was changed after beta failed")
		}
		// Retrying the members that didn't get it.
		ge.ph["beta"].SetAppSudo(true)
		path := cnames + "?members=" + itoa(ge.ids["beta"]) + "&members=" + itoa(ge.ids["gamma"])
		mustStatus(t, ge.admin.do(http.MethodPost, path, gen.CNAMEInput{Alias: "media.lab", Target: "nas.lab", Reason: reason("x")}), http.StatusOK)
	})

	t.Run("drift and reconcile", func(t *testing.T) {
		// alpha gains records directly: one the app could write, one it couldn't; beta has one only it has.
		h, c := ge.ph["alpha"].LocalDNS()
		ge.ph["alpha"].SetLocalDNS(append(h, "10.0.0.20 web.lab", "10.0.0.21 a.lab b.lab"), append(c, "x.lab,web.lab,60"))
		hb, cb := ge.ph["beta"].LocalDNS()
		ge.ph["beta"].SetLocalDNS(append(hb, "10.0.0.99 stale.lab"), cb)
		ge.ph["beta"].Handle(nil)
		ge.ph["gamma"].SetLocalDNS([]string{"10.0.0.5  NAS.lab"}, mustCNAMEs(ge, "alpha"))
		if _, err := d.Check(context.Background(), ge.groupID); err != nil {
			t.Fatal(err)
		}
		rep := decode[gen.DriftReport](t, ge.admin.do(http.MethodGet, ge.driftPath(""), nil))
		if rep.LocalDns == nil {
			t.Fatal("no local DNS drift for an admin")
		}
		var got []string
		for _, x := range *rep.LocalDns {
			s := x.Instance + " " + string(x.RecordKind) + " " + x.Key + " " + string(x.Difference)
			if x.Writable != nil && !*x.Writable {
				s += " unwritable"
			}
			got = append(got, s)
		}
		want := []string{
			"beta cname x.lab,web.lab,60 missing",
			"beta record 10.0.0.20 web.lab missing",
			"beta record 10.0.0.21 a.lab b.lab missing unwritable",
			"beta record 10.0.0.99 stale.lab extra",
			"gamma record 10.0.0.20 web.lab missing",
			"gamma record 10.0.0.21 a.lab b.lab missing unwritable",
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("drift %v, want %v", got, want)
		}
		if rep.Counts.LocalDns != 6 {
			t.Errorf("counts %+v", rep.Counts)
		}
		viewer := ge.userWith("drifter", rbac.DriftView)
		if r := decode[gen.DriftReport](t, viewer.do(http.MethodGet, ge.driftPath(""), nil)); r.LocalDns != nil || r.Counts.LocalDns != 6 {
			t.Errorf("drift.view alone sees %+v", r.LocalDns)
		}
		if out := decode[gen.LocalDNS](t, ge.admin.do(http.MethodGet, ge.path("/local-dns"), nil)); out.Drifted == nil || !*out.Drifted {
			t.Errorf("drifted %v", out.Drifted)
		}

		restarts := ge.ph["beta"].Restarts()
		res := ge.admin.do(http.MethodPost, "/api/v1/instance-groups/"+itoa(ge.groupID)+"/reconcile", gen.ReconcileInput{All: ptrTrue()})
		if res.Code != http.StatusMultiStatus {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		out := decode[gen.ReconcileResult](t, res)
		var items []string
		for _, r := range out.Results {
			if r.Item != "local_dns" {
				continue
			}
			s := r.Instance + " " + *r.Key + " " + string(r.Action) + " " + string(r.Status)
			if r.Error != nil {
				s += " " + r.Error.Code
			}
			items = append(items, s)
		}
		slices.Sort(items)
		wantItems := []string{
			"beta 10.0.0.20 web.lab add ok",
			"beta 10.0.0.21 a.lab b.lab add failed validation_failed",
			"beta 10.0.0.99 stale.lab delete ok",
			"beta x.lab,web.lab,60 add ok",
			"gamma 10.0.0.20 web.lab add ok",
			"gamma 10.0.0.21 a.lab b.lab add failed validation_failed",
		}
		if !slices.Equal(items, wantItems) {
			t.Errorf("reconcile %v, want %v", items, wantItems)
		}
		hb, cb = ge.ph["beta"].LocalDNS()
		if !slices.Contains(hb, "10.0.0.20 web.lab") || slices.Contains(hb, "10.0.0.99 stale.lab") || !slices.Contains(cb, "x.lab,web.lab,60") {
			t.Errorf("beta after reconcile %q %q", hb, cb)
		}
		if got := ge.ph["beta"].Restarts() - restarts; got != 1 {
			t.Errorf("beta restarted %d times for one CNAME", got)
		}
		if got := ge.ph["gamma"].Restarts(); got == 0 {
			t.Error("gamma never restarted")
		}
	})

	t.Run("a member that is down is skipped and the write goes on", func(t *testing.T) {
		ge.unreachable("beta")
		t.Cleanup(func() { ge.ph["beta"].Handle(nil) })
		res := ge.admin.do(http.MethodPost, cnames, gen.CNAMEInput{Alias: "down.lab", Target: "nas.lab", Reason: reason("x")})
		got := summarise(results(t, res))
		if !slices.Equal(got, []string{"alpha:ok", "beta:skipped:pihole_unreachable", "gamma:ok"}) {
			t.Errorf("results %v", got)
		}
	})
}

func mustCNAMEs(ge *groupEnv, name string) []string {
	_, c := ge.ph[name].LocalDNS()
	return c
}
