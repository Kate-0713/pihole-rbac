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

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

const (
	adsList    = "https://lists.example/ads.txt"
	secretList = "https://user:hunter2@lists.example/private.txt"
	secretShow = "https://xxxxx@lists.example/private.txt"
)

// withLoginSettings gives the server a loginsettings.Service, for the general settings.
func withLoginSettings(t *testing.T, svc **loginsettings.Service) func(*Options) {
	return func(o *Options) {
		s := &loginsettings.Service{
			Store: o.Store, Audit: o.Audit, Secrets: testSecrets{}, Sessions: o.Sessions,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if err := s.Load(context.Background()); err != nil {
			t.Fatal(err)
		}
		o.LoginSettings = s
		if svc != nil {
			*svc = s
		}
	}
}

func listNamed(t *testing.T, ph *piholetest.Server, address, listType string) (piholetest.List, bool) {
	t.Helper()
	ls := ph.Lists()
	i := slices.IndexFunc(ls, func(l piholetest.List) bool { return l.Address == address && l.Type == listType })
	if i < 0 {
		return piholetest.List{}, false
	}
	return ls[i], true
}

func TestListReads(t *testing.T) {
	te := newTargetEnv(t)
	kids := te.ph.AddGroup("kids")
	te.ph.SetGravityState(5000, 1_790_000_000) // gravity last ran at the fake's starting time
	te.ph.AddList(piholetest.List{Address: adsList, Type: "block", Comment: "ads", Enabled: true, Status: 1, Number: 5000,
		InvalidDomains: 2, DateUpdated: 1_789_999_000, DateAdded: 1_780_000_000})
	te.ph.AddList(piholetest.List{Address: "ftp://lists.example/old.txt", Type: "block", Enabled: true, Status: 4, DateAdded: 1_780_000_000})
	te.ph.AddList(piholetest.List{Address: secretList, Type: "allow", Groups: []int{kids}, Enabled: true, Status: 3, DateAdded: 1_780_000_000})
	te.ph.Advance(100)
	te.ph.AddList(piholetest.List{Address: "https://lists.example/new.txt", Type: "block", Enabled: true}) // after the last run
	te.ph.AddList(piholetest.List{Address: "file:///etc/pihole/local.txt", Type: "block", Enabled: false})

	res := te.admin.do(http.MethodGet, te.path("/lists"), nil)
	mustStatus(t, res, http.StatusOK)
	out := decode[gen.PiholeListList](t, res)
	if out.GravityLastUpdate == nil || out.GravityLastUpdate.Unix() != 1_790_000_000 || out.Members != nil || out.Drifted != nil {
		t.Errorf("answer %+v", out)
	}
	type row struct {
		address, status string
		domains         int
		needs           bool
		marks           string
	}
	var got []row
	for _, l := range out.Lists {
		var marks []string
		for _, m := range l.Marks {
			marks = append(marks, string(m))
		}
		got = append(got, row{l.Address, string(l.Status), l.Domains, l.NeedsGravity, strings.Join(marks, ",")})
	}
	want := []row{
		{adsList, "updated", 5000, false, ""},
		{"ftp://lists.example/old.txt", "failed", 0, false, "scheme"},
		{secretShow, "cached", 0, false, "credentials"},
		{"https://lists.example/new.txt", "never", 0, true, ""},
		{"file:///etc/pihole/local.txt", "never", 0, false, "file"}, // disabled, so not waiting
	}
	if !slices.Equal(got, want) {
		t.Errorf("lists\n%v\nwant\n%v", got, want)
	}
	if strings.Contains(res.Body.String(), "hunter2") {
		t.Error("the password in an address was sent")
	}
	if l := out.Lists[0]; l.UpdatedAt == nil || l.InvalidDomains != 2 || l.Comment != "ads" || !slices.Equal(l.Groups, []int{0}) {
		t.Errorf("ads list %+v", l)
	}
	if l := out.Lists[2]; !slices.Equal(l.Groups, []int{kids}) || l.Type != "allow" {
		t.Errorf("secret list %+v", l)
	}
}

func TestListWrites(t *testing.T) {
	te := newTargetEnv(t)
	kids := te.ph.AddGroup("kids")
	te.ph.AddList(piholetest.List{Address: secretList, Type: "block", Enabled: true})

	t.Run("add", func(t *testing.T) {
		r := okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPost, te.path("/lists"),
			gen.PiholeListInput{Address: "  " + adsList + " ", Type: "block", Comment: strp("ads"), Groups: intsp(0, kids)}))
		l, ok := listNamed(t, te.ph, adsList, "block")
		if !ok || !l.Enabled || l.Comment != "ads" || !slices.Equal(l.Groups, []int{0, kids}) {
			t.Fatalf("list %+v", l)
		}
		if r.Entry == nil || r.Entry.Address != adsList || !r.Entry.NeedsGravity || r.Entry.Status != "never" {
			t.Errorf("entry %+v", r.Entry)
		}
		row, detail := te.lastAudit()
		if row.Action != audit.ActionListAdd || detail["address"] != adsList || detail["type"] != "block" || detail["enabled"] != true {
			t.Errorf("audit %s %v", row.Action, detail)
		}
		if g, _ := detail["groups"].([]any); len(g) != 2 || g[1] != "kids" {
			t.Errorf("audit groups %v", detail["groups"])
		}
		// Without groups the list goes in Default; disabled, it doesn't wait for gravity.
		r = okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPost, te.path("/lists"),
			gen.PiholeListInput{Address: adsList, Type: "allow", Enabled: ptr(false)}))
		if l, _ := listNamed(t, te.ph, adsList, "allow"); l.Enabled || !slices.Equal(l.Groups, []int{0}) || r.Entry.NeedsGravity {
			t.Errorf("allow list %+v, entry %+v", l, r.Entry)
		}
		res := te.admin.do(http.MethodPost, te.path("/lists"), gen.PiholeListInput{Address: adsList, Type: "block"})
		if res.Code != http.StatusBadRequest || res.errorCode() != "pihole_rejected" {
			t.Errorf("a taken address: %d %s", res.Code, res.Body)
		}
	})

	t.Run("addresses are checked before anything is sent", func(t *testing.T) {
		for address, reason := range map[string]string{
			"":                                 "invalid",
			"https://lists.example/a b":        "invalid",
			"https://u:p@lists.example/l.txt":  "credentials",
			"ftp://lists.example/l.txt":        "scheme",
			"sftp://lists.example/l.txt":       "scheme",
			"lists.example/l.txt":              "scheme",
			"file:///etc/pihole/list.txt":      "file", // allow_file_lists is off
			"https://lists.example/\u0007.txt": "invalid",
		} {
			writes := len(te.piholeWrites())
			res := te.admin.do(http.MethodPost, te.path("/lists"), gen.PiholeListInput{Address: address, Type: "block"})
			d := errorDetails(t, res)
			if res.Code != http.StatusBadRequest || d["field"] != "address" || d["reason"] != reason {
				t.Errorf("%q: %d %s, want reason %s", address, res.Code, res.Body, reason)
			}
			if strings.Contains(res.Body.String(), "u:p@") {
				t.Errorf("%q: the refusal repeats the address", address)
			}
			if len(te.piholeWrites()) != writes {
				t.Errorf("%q was sent to Pi-hole", address)
			}
		}
		if res := te.admin.do(http.MethodPost, te.path("/lists"), map[string]any{"address": adsList, "type": "deny"}); res.Code != http.StatusBadRequest {
			t.Errorf("type deny: %d %s", res.Code, res.Body)
		}
	})

	t.Run("change", func(t *testing.T) {
		te.ph.Advance(10)
		r := okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPatch, te.path("/lists"),
			gen.PiholeListUpdate{Address: adsList, Type: "allow", Enabled: ptr(true), Comment: strp("work")}))
		if l, _ := listNamed(t, te.ph, adsList, "allow"); !l.Enabled || l.Comment != "work" || !slices.Equal(l.Groups, []int{0}) {
			t.Errorf("list %+v", l)
		}
		if !r.Entry.NeedsGravity {
			t.Error("a list enabled again doesn't say it waits for gravity")
		}
		_, detail := te.lastAudit()
		if detail["enabled_before"] != false || detail["enabled_after"] != true || detail["comment_changed"] != true {
			t.Errorf("audit %v", detail)
		}
		// Groups only: the comment and enabled flag are kept, though Pi-hole's PUT would reset them.
		okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPatch, te.path("/lists"),
			gen.PiholeListUpdate{Address: adsList, Type: "allow", Groups: intsp(kids)}))
		if l, _ := listNamed(t, te.ph, adsList, "allow"); !l.Enabled || l.Comment != "work" || !slices.Equal(l.Groups, []int{kids}) {
			t.Errorf("list %+v", l)
		}
		// Nothing to change: nothing sent, nothing audited.
		writes, rows := len(te.piholeWrites()), te.auditCount()
		okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPatch, te.path("/lists"),
			gen.PiholeListUpdate{Address: adsList, Type: "allow", Comment: strp("work")}))
		if len(te.piholeWrites()) != writes || te.auditCount() != rows {
			t.Error("an unchanged list was written or audited")
		}
		// A list that isn't there is a 404, and the PUT that would create it is never sent.
		res := te.admin.do(http.MethodPatch, te.path("/lists"), gen.PiholeListUpdate{Address: "https://lists.example/none.txt", Type: "block", Comment: strp("x")})
		if res.Code != http.StatusNotFound || len(te.piholeWrites()) != writes {
			t.Errorf("missing list: %d %s", res.Code, res.Body)
		}
		if res := te.admin.do(http.MethodPatch, te.path("/lists"), gen.PiholeListUpdate{Address: adsList, Type: "allow"}); res.Code != http.StatusBadRequest {
			t.Errorf("no change given: %d %s", res.Code, res.Body)
		}
	})

	t.Run("a list with a password is named by its redacted address", func(t *testing.T) {
		okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPatch, te.path("/lists"),
			gen.PiholeListUpdate{Address: secretShow, Type: "block", Comment: strp("private")}))
		if l, _ := listNamed(t, te.ph, secretList, "block"); l.Comment != "private" {
			t.Errorf("list %+v", l)
		}
		row, detail := te.lastAudit()
		if detail["address"] != secretShow || strings.Contains(row.Detail, "hunter2") {
			t.Errorf("audit %s", row.Detail)
		}
		// Two lists that look the same once redacted can't be told apart.
		te.ph.AddList(piholetest.List{Address: "https://other:pw@lists.example/private.txt", Type: "block", Enabled: true})
		res := te.admin.do(http.MethodPatch, te.path("/lists"), gen.PiholeListUpdate{Address: secretShow, Type: "block", Comment: strp("x")})
		if res.Code != http.StatusConflict || res.errorCode() != "conflict" {
			t.Errorf("ambiguous: %d %s", res.Code, res.Body)
		}
		// The real address still names one exactly.
		mustStatus(t, te.admin.do(http.MethodDelete, te.path("/lists"), gen.PiholeListKey{Address: "https://other:pw@lists.example/private.txt", Type: "block"}), http.StatusOK)
		mustStatus(t, te.admin.do(http.MethodDelete, te.path("/lists"), gen.PiholeListKey{Address: secretShow, Type: "block"}), http.StatusOK)
		if _, ok := listNamed(t, te.ph, secretList, "block"); ok {
			t.Error("not deleted")
		}
		if row, _ := te.lastAudit(); row.Action != audit.ActionListDelete || strings.Contains(row.Detail, "hunter2") {
			t.Errorf("audit %s %s", row.Action, row.Detail)
		}
	})

	t.Run("delete", func(t *testing.T) {
		mustStatus(t, te.admin.do(http.MethodDelete, te.path("/lists"), gen.PiholeListKey{Address: adsList, Type: "allow"}), http.StatusOK)
		if _, ok := listNamed(t, te.ph, adsList, "allow"); ok {
			t.Error("not deleted")
		}
		if _, ok := listNamed(t, te.ph, adsList, "block"); !ok {
			t.Error("the block list of the same address was deleted")
		}
		_, detail := te.lastAudit()
		if detail["comment"] != "work" || detail["enabled"] != true {
			t.Errorf("audit %v", detail)
		}
		if res := te.admin.do(http.MethodDelete, te.path("/lists"), gen.PiholeListKey{Address: adsList, Type: "allow"}); res.Code != http.StatusNotFound {
			t.Errorf("deleting again: %d %s", res.Code, res.Body)
		}
	})
}

// TestListPermissions: reading needs lists.view and writing lists.edit, on the target; neither gives the other.
func TestListPermissions(t *testing.T) {
	te := newTargetEnv(t)
	te.ph.AddList(piholetest.List{Address: adsList, Type: "block", Enabled: true})
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.ListsView, "instance", te.id))
	te.addGrantUser("editor", "editor-password-1", grant(rbac.ListsEdit, "instance", te.id))
	te.addGrantUser("domains", "domains-password-1", grant(rbac.DomainsEdit, "instance", te.id), grant(rbac.DomainsView, "instance", te.id))
	viewer := te.loggedIn("viewer", "viewer-password-1")
	editor := te.loggedIn("editor", "editor-password-1")
	domains := te.loggedIn("domains", "domains-password-1")

	mustStatus(t, viewer.do(http.MethodGet, te.path("/lists"), nil), http.StatusOK)
	for _, c := range []struct {
		who    *client
		method string
		body   any
		perm   rbac.Permission
	}{
		{editor, http.MethodGet, nil, rbac.ListsView},
		{domains, http.MethodGet, nil, rbac.ListsView},
		{viewer, http.MethodPost, gen.PiholeListInput{Address: "https://lists.example/x.txt", Type: "block"}, rbac.ListsEdit},
		{viewer, http.MethodPatch, gen.PiholeListUpdate{Address: adsList, Type: "block", Comment: strp("x")}, rbac.ListsEdit},
		{domains, http.MethodDelete, gen.PiholeListKey{Address: adsList, Type: "block"}, rbac.ListsEdit},
	} {
		res := c.who.do(c.method, te.path("/lists"), c.body)
		if res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != string(c.perm) {
			t.Errorf("%s: %d %s, want 403 for %s", c.method, res.Code, res.Body, c.perm)
		}
	}
	mustStatus(t, editor.do(http.MethodPatch, te.path("/lists"), gen.PiholeListUpdate{Address: adsList, Type: "block", Comment: strp("x")}), http.StatusOK)
	if w := te.piholeWrites(); len(w) != 1 {
		t.Errorf("writes %v", w)
	}
}

// TestFileListsSetting: file: lists are refused until an admin turns allow_file_lists on, which is audited, and
// turning it off again leaves existing ones alone.
func TestFileListsSetting(t *testing.T) {
	var svc *loginsettings.Service
	te := newTargetEnv(t, withLoginSettings(t, &svc))
	const local = "file:///etc/pihole/local.txt"
	add := func() response {
		return te.admin.do(http.MethodPost, te.path("/lists"), gen.PiholeListInput{Address: local, Type: "block"})
	}
	if res := add(); res.Code != http.StatusBadRequest || errorDetails(t, res)["reason"] != "file" {
		t.Fatalf("before: %d %s", res.Code, res.Body)
	}
	g := decode[gen.GeneralSettings](t, te.admin.do(http.MethodGet, "/api/v1/settings/general", nil))
	if g.AllowFileLists {
		t.Error("on by default")
	}
	set := func(on *bool) gen.GeneralSettings {
		res := te.admin.do(http.MethodPut, "/api/v1/settings/general", gen.GeneralSettingsInput{
			SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60, AllowFileLists: on,
		})
		mustStatus(t, res, http.StatusOK)
		return decode[gen.GeneralSettings](t, res)
	}
	if g := set(ptr(true)); !g.AllowFileLists || !svc.AllowFileLists() {
		t.Errorf("after turning it on: %+v", g)
	}
	row, detail := te.lastAudit()
	if row.Action != audit.ActionSettingsUpdate || detail["allow_file_lists"] != true {
		t.Errorf("audit %s %v", row.Action, detail)
	}
	if ch, _ := detail["changed"].([]any); !slices.Contains(ch, any("allow_file_lists")) {
		t.Errorf("changed %v", detail["changed"])
	}
	okResult[gen.PiholeListWriteResult](te, add())
	if g := set(nil); !g.AllowFileLists { // a save that leaves it out keeps it
		t.Error("a save without it turned it off")
	}
	set(ptr(false))
	// The existing file: list can still be changed and deleted, and is marked.
	okResult[gen.PiholeListWriteResult](te, te.admin.do(http.MethodPatch, te.path("/lists"), gen.PiholeListUpdate{Address: local, Type: "block", Enabled: ptr(false)}))
	out := decode[gen.PiholeListList](t, te.admin.do(http.MethodGet, te.path("/lists"), nil))
	if len(out.Lists) != 1 || !slices.Equal(out.Lists[0].Marks, []gen.PiholeListMarks{"file"}) {
		t.Errorf("lists %+v", out.Lists)
	}
	// It survives a restart.
	set(ptr(true))
	again := &loginsettings.Service{Store: te.st, Audit: te.srv.Audit, Secrets: testSecrets{}}
	if err := again.Load(context.Background()); err != nil || !again.AllowFileLists() {
		t.Errorf("after a restart: %v, %v", again.AllowFileLists(), err)
	}
}

// TestGroupLists: lists through a mirrored group are written to every member, matched by address and type with
// groups translated by name; read with the primary's settings and every member's own status; and diffed and
// reconciled like domains.
func TestGroupLists(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	kidsA := ge.ph["alpha"].AddGroup("kids")
	kidsB := ge.ph["beta"].AddGroup("kids")
	ge.ph["gamma"].AddGroup("kids")

	res := ge.admin.do(http.MethodPost, ge.path("/lists"), gen.PiholeListInput{Address: adsList, Type: "block", Groups: intsp(kidsA)})
	mustStatus(t, res, http.StatusOK)
	if l, ok := listNamed(t, ge.ph["beta"], adsList, "block"); !ok || !slices.Equal(l.Groups, []int{kidsB}) {
		t.Errorf("beta's list %+v", l)
	}
	if rows, details := ge.auditSince(0); len(rows) == 0 || details[len(details)-1]["via"] != ge.target {
		t.Errorf("audit %v", details)
	}

	// beta's last download failed; gamma has never run gravity since the list was added; alpha is fine.
	mustRun := func(name string, g piholetest.GravityRun) {
		ge.ph[name].SetGravity(g)
		if err := ge.srv.Instances.Pool.Do(context.Background(), ge.ids[name], func(ctx context.Context, cl *piholeapi.Client) error {
			return cl.RunGravity(ctx, func(string) {})
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustRun("alpha", piholetest.GravityRun{})
	mustRun("beta", piholetest.GravityRun{Statuses: map[string]int{adsList: 4}})
	ge.ph["alpha"].Advance(1)
	ge.ph["alpha"].AddList(piholetest.List{Address: secretList, Type: "allow", Enabled: true}) // only on alpha, after its run

	out := decode[gen.PiholeListList](t, ge.admin.do(http.MethodGet, ge.path("/lists"), nil))
	if out.Members == nil || len(*out.Members) != 3 {
		t.Fatalf("members %+v", out.Members)
	}
	type row struct {
		member, state, status string
		needs                 bool
	}
	describe := func(l gen.PiholeList) []row {
		var rows []row
		for _, m := range *l.Members {
			r := row{member: m.Instance, state: string(m.State)}
			if m.Status != nil {
				r.status, r.needs = string(*m.Status), *m.NeedsGravity
			}
			rows = append(rows, r)
		}
		return rows
	}
	ads, secret := out.Lists[0], out.Lists[1]
	if ads.Status != "updated" || !ads.NeedsGravity || !slices.Equal(ads.Groups, []int{kidsA}) {
		t.Errorf("ads list %+v", ads)
	}
	if got, want := describe(ads), []row{{"alpha", "ok", "updated", false}, {"beta", "ok", "failed", false}, {"gamma", "ok", "never", true}}; !slices.Equal(got, want) {
		t.Errorf("ads members %v, want %v", got, want)
	}
	if got, want := describe(secret), []row{{"alpha", "ok", "never", true}, {"beta", "missing", "", false}, {"gamma", "missing", "", false}}; !slices.Equal(got, want) {
		t.Errorf("secret members %v, want %v", got, want)
	}
	if secret.Address != secretShow || strings.Contains(ge.admin.do(http.MethodGet, ge.path("/lists"), nil).Body.String(), "hunter2") {
		t.Error("a password was shown")
	}

	t.Run("a member that can't be read", func(t *testing.T) {
		ge.down("gamma")
		out := decode[gen.PiholeListList](t, ge.admin.do(http.MethodGet, ge.path("/lists"), nil))
		if m := (*out.Members)[2]; m.Instance != "gamma" || m.Status != "failed" {
			t.Errorf("gamma %+v", m)
		}
		if m := (*out.Lists[0].Members)[2]; m.State != "unreadable" || m.Status != nil {
			t.Errorf("gamma's list %+v", m)
		}
		ge.ph["gamma"].Handle(nil)
		ge.down("alpha")
		if res := ge.admin.do(http.MethodGet, ge.path("/lists"), nil); res.Code != http.StatusBadGateway {
			t.Errorf("primary down: %d %s", res.Code, res.Body)
		}
		ge.ph["alpha"].Handle(nil)
	})

	t.Run("change on a member without the list", func(t *testing.T) {
		res := ge.admin.do(http.MethodPatch, ge.path("/lists"), gen.PiholeListUpdate{Address: secretShow, Type: "allow", Enabled: ptr(false)})
		if res.Code != http.StatusMultiStatus {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		if got := summarise(results(t, res)); !slices.Equal(got, []string{"alpha:ok", "beta:failed:not_found", "gamma:failed:not_found"}) {
			t.Errorf("results %v", got)
		}
		if _, ok := listNamed(t, ge.ph["beta"], secretList, "allow"); ok {
			t.Error("the change created the list on beta")
		}
		okResult := ge.admin.do(http.MethodPatch, ge.path("/lists"), gen.PiholeListUpdate{Address: secretShow, Type: "allow", Enabled: ptr(true)})
		if okResult.Code != http.StatusMultiStatus {
			t.Errorf("%d", okResult.Code)
		}
	})

	t.Run("drift and reconcile", func(t *testing.T) {
		ge.ph["beta"].AddList(piholetest.List{Address: "https://lists.example/beta.txt", Type: "block", Enabled: true})
		ge.ph["alpha"].AddList(piholetest.List{Address: "file:///etc/pihole/local.txt", Type: "block", Enabled: true})
		ge.ph["alpha"].AddList(piholetest.List{Address: "https://lists.example/new.txt", Type: "block", Enabled: true})
		mustStatus(t, ge.admin.do(http.MethodPost, ge.driftPath("/check"), nil), http.StatusOK)
		rep := decode[gen.DriftReport](t, ge.admin.do(http.MethodGet, ge.driftPath(""), nil))
		if rep.Lists == nil || rep.Counts.Lists != len(*rep.Lists) || rep.Counts.Lists != 7 {
			t.Fatalf("report lists %+v counts %+v", rep.Lists, rep.Counts)
		}
		for _, l := range *rep.Lists {
			if strings.Contains(l.Address, "hunter2") {
				t.Error("a password in the drift report")
			}
		}
		// Without lists.view, only the count.
		ge.addGrantUser("drift", "drift-password-1", grant(rbac.DriftView, "group", ge.groupID))
		other := decode[gen.DriftReport](t, ge.loggedIn("drift", "drift-password-1").do(http.MethodGet, ge.driftPath(""), nil))
		if other.Lists != nil || other.Counts.Lists != 7 {
			t.Errorf("without lists.view: %+v %+v", other.Lists, other.Counts)
		}

		res := ge.admin.do(http.MethodPost, ge.reconcilePath(), gen.ReconcileInput{Lists: &[]gen.ReconcileList{
			{InstanceId: ge.ids["beta"], Address: secretShow, Type: "allow"},
			{InstanceId: ge.ids["beta"], Address: "file:///etc/pihole/local.txt", Type: "block"},
			{InstanceId: ge.ids["beta"], Address: "https://lists.example/beta.txt", Type: "block"},
			{InstanceId: ge.ids["beta"], Address: "https://lists.example/new.txt", Type: "block"},
		}})
		if res.Code != http.StatusMultiStatus {
			t.Fatalf("reconcile: %d %s", res.Code, res.Body)
		}
		out := decode[gen.ReconcileResult](t, res)
		var got []string
		for _, r := range out.Results {
			s := string(r.Item) + ":" + string(r.Action) + ":" + string(r.Status) + ":" + *r.Address
			if r.NeedsGravity != nil && *r.NeedsGravity {
				s += ":gravity"
			}
			if r.Error != nil {
				s += ":" + r.Error.Code
			}
			got = append(got, s)
		}
		slices.Sort(got)
		// The app's rules for new addresses apply to reconcile too: neither the file: list (allow_file_lists is off) nor
		// the one with a password is copied.
		want := []string{
			"list:add:failed:file:///etc/pihole/local.txt:validation_failed",
			"list:add:failed:" + secretShow + ":validation_failed",
			"list:add:ok:https://lists.example/new.txt:gravity",
			"list:delete:ok:https://lists.example/beta.txt",
		}
		if !slices.Equal(got, want) {
			t.Errorf("results\n%v\nwant\n%v", got, want)
		}
		if _, ok := listNamed(t, ge.ph["beta"], secretList, "allow"); ok {
			t.Error("the list with a password was copied")
		}
		if _, ok := listNamed(t, ge.ph["beta"], "https://lists.example/new.txt", "block"); !ok {
			t.Error("new.txt wasn't copied")
		}
		if strings.Contains(res.Body.String(), "hunter2") {
			t.Error("a password in the reconcile answer")
		}
		rows := ge.auditRows()
		if last := rows[len(rows)-1]; last.Action != audit.ActionGroupReconcile || strings.Contains(last.Detail, "hunter2") ||
			!strings.Contains(last.Detail, "list allow "+secretShow) {
			t.Errorf("audit %s %s", last.Action, last.Detail)
		}
	})
}
