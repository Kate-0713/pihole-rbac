// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// auditBase is when seedAudit's rows start: an hour apart from here.
var auditBase = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// seedAudit writes an instance and five rows, oldest first, with IDs following whatever rows the test already has.
func (e *testEnv) seedAudit() (instanceID int64) {
	e.t.Helper()
	ctx := context.Background()
	err := e.st.WithTx(ctx, func(q *db.Queries) error {
		var err error
		instanceID, err = q.CreateInstance(ctx, db.CreateInstanceParams{
			Name: "pihole1", BaseUrl: "http://pihole1.lan", TlsMode: "verify", CreatedAt: 1,
		})
		if err != nil {
			return err
		}
		rows := []audit.Entry{
			{Username: "mallory", Action: audit.ActionLogin, Err: errors.New("invalid username or password"), IP: "10.0.0.9"},
			{Username: "alice", Action: audit.ActionDomainAdd, Target: "i-1", InstanceID: instanceID, InstanceName: "pihole1",
				Detail: map[string]any{"domain": "=HYPERLINK(\"http://evil\")"}},
			{Username: "alice", Action: audit.ActionDomainDelete, Target: "i-1", InstanceID: instanceID, InstanceName: "pihole1",
				Detail: map[string]any{"domain": "example.com"}},
			{Username: "bob", Action: audit.ActionUserDisable, Target: "user:carol"},
			{Username: "-carol", Action: audit.ActionSettingsUpdate, Target: "settings:general",
				Err: errors.New("refused")},
		}
		for i, r := range rows {
			r.At = auditBase.Add(time.Duration(i) * time.Hour)
			if _, err := audit.Insert(ctx, q, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return instanceID
}

func auditQuery(v url.Values) string {
	if len(v) == 0 {
		return "/api/v1/audit"
	}
	return "/api/v1/audit?" + v.Encode()
}

func auditActionsOf(l gen.AuditList) []string {
	var out []string
	for _, e := range l.Entries {
		out = append(out, e.Action)
	}
	return out
}

func TestListAudit(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("bob", "bob-password-1", rbac.AuditView)
	e.addRoleUser("dora", "dora-password-1", rbac.DomainsView, rbac.UsersManage)
	c := e.loggedIn("bob", "bob-password-1") // writes a login row first
	instanceID := e.seedAudit()
	seeded := []string{"settings_update", "user_disable", "domain_delete", "domain_add", "login"}

	all := decode[gen.AuditList](t, c.do(http.MethodGet, auditQuery(nil), nil))
	if got := auditActionsOf(all); !slices.Equal(got, append(slices.Clone(seeded), "login")) {
		t.Fatalf("newest first: %v", got)
	}
	if all.NextCursor != nil {
		t.Errorf("one page has a cursor")
	}
	add := all.Entries[3]
	if add.InstanceId == nil || *add.InstanceId != instanceID || add.InstanceName != "pihole1" || add.Target != "i-1" ||
		add.Result != gen.AuditEntryResultSuccess || add.Detail["domain"] != "=HYPERLINK(\"http://evil\")" ||
		!add.At.Equal(auditBase.Add(time.Hour)) || add.UserId != nil {
		t.Errorf("domain_add entry: %+v", add)
	}
	failed := all.Entries[4]
	if failed.Result != gen.AuditEntryResultFailure || failed.Detail["error"] != "invalid username or password" ||
		failed.Ip != "10.0.0.9" || failed.InstanceId != nil {
		t.Errorf("failed login entry: %+v", failed)
	}
	if bobLogin := all.Entries[5]; bobLogin.UserId == nil || bobLogin.Username != "bob" {
		t.Errorf("bob's login has no user ID: %+v", bobLogin)
	}

	from := auditBase.Add(time.Hour).Format(time.RFC3339)
	to := auditBase.Add(3 * time.Hour).Format(time.RFC3339)
	for _, tt := range []struct {
		name  string
		query url.Values
		want  []string
	}{
		{"user", url.Values{"user": {"alice"}}, []string{"domain_delete", "domain_add"}},
		{"user is exact", url.Values{"user": {"ali"}}, nil},
		{"one action", url.Values{"action": {"user_disable"}}, []string{"user_disable"}},
		{"two actions", url.Values{"action": {"domain_add", "settings_update"}}, []string{"settings_update", "domain_add"}},
		{"unknown action", url.Values{"action": {"no_such_action"}}, nil},
		{"target", url.Values{"target": {"user:carol"}}, []string{"user_disable"}},
		{"instance", url.Values{"instance_id": {fmt.Sprint(instanceID)}}, []string{"domain_delete", "domain_add"}},
		{"failures", url.Values{"result": {"failure"}}, []string{"settings_update", "login"}},
		{"from is inclusive, to exclusive", url.Values{"from": {from}, "to": {to}}, []string{"domain_delete", "domain_add"}},
		{"from only", url.Values{"from": {auditBase.Add(4 * time.Hour).Format(time.RFC3339)}, "user": {"-carol"}},
			[]string{"settings_update"}},
		{"everything at once", url.Values{"user": {"alice"}, "action": {"domain_add"}, "result": {"success"},
			"instance_id": {fmt.Sprint(instanceID)}, "target": {"i-1"}}, []string{"domain_add"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := c.do(http.MethodGet, auditQuery(tt.query), nil)
			mustStatus(t, res, http.StatusOK)
			if got := auditActionsOf(decode[gen.AuditList](t, res)); !slices.Equal(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	// Paging: two at a time, no repeats or gaps, even with a row written between pages.
	var paged []int64
	q := url.Values{"limit": {"2"}}
	for pages := 0; ; pages++ {
		l := decode[gen.AuditList](t, c.do(http.MethodGet, auditQuery(q), nil))
		for _, en := range l.Entries {
			paged = append(paged, en.Id)
		}
		if pages == 0 {
			e.loggedIn("bob", "bob-password-1") // a newer row mustn't shift the pages
		}
		if l.NextCursor == nil {
			break
		}
		q.Set("cursor", *l.NextCursor)
	}
	var want []int64
	for _, en := range all.Entries {
		want = append(want, en.Id)
	}
	if !slices.Equal(paged, want) {
		t.Errorf("paged IDs %v, want %v", paged, want)
	}

	for _, bad := range []url.Values{
		{"limit": {"0"}},
		{"limit": {"201"}},
		{"cursor": {"nope"}},
		{"cursor": {"YTow"}}, // "a:0"
		{"action": {"Login"}},
		{"action": {"domain-add"}},
		{"result": {"maybe"}},
		{"instance_id": {"0"}},
		{"instance_id": {"x"}},
		{"from": {"yesterday"}},
		{"from": {to}, "to": {from}},
		{"from": {from}, "to": {from}},
		{"to": {"1960-01-01T00:00:00Z"}},
		{"user": {strings.Repeat("u", maxAuditUser+1)}},
		{"target": {strings.Repeat("t", maxAuditTarget+1)}},
		{"action": slices.Repeat([]string{"login"}, maxAuditActions+1)},
	} {
		res := c.do(http.MethodGet, auditQuery(bad), nil)
		if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" {
			t.Errorf("%v: %d %s", bad, res.Code, res.Body)
		}
	}

	// Without audit.view: 403 for both the list and the export, whatever else the user holds.
	d := e.loggedIn("dora", "dora-password-1")
	for _, path := range []string{"/api/v1/audit", "/api/v1/audit/export"} {
		if res := d.do(http.MethodGet, path, nil); res.Code != http.StatusForbidden {
			t.Errorf("%s without audit.view: %d", path, res.Code)
		}
	}
	if res := e.client("10.0.0.2:1").do(http.MethodGet, "/api/v1/audit", nil); res.Code != http.StatusUnauthorized {
		t.Errorf("without a session: %d", res.Code)
	}
}

func readCSV(t *testing.T, res response) [][]string {
	t.Helper()
	recs, err := csv.NewReader(bytes.NewReader(res.Body.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("CSV: %v\n%s", err, res.Body)
	}
	return recs
}

func TestExportAudit(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("bob", "bob-password-1", rbac.AuditView)
	c := e.loggedIn("bob", "bob-password-1")
	instanceID := e.seedAudit()

	res := c.do(http.MethodGet, "/api/v1/audit/export", nil)
	mustStatus(t, res, http.StatusOK)
	if ct := res.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("Content-Type %q", ct)
	}
	if cd := res.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="pihole-rbac-audit-`) ||
		!strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("Content-Disposition %q", cd)
	}
	if cc := res.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	recs := readCSV(t, res)
	if !slices.Equal(recs[0], auditCSVHeader) || len(recs) != 7 {
		t.Fatalf("%d records, header %v", len(recs), recs[0])
	}
	add := recs[4]
	if add[1] != "2026-10-01T13:00:00.000Z" || add[2] != "alice" || add[3] != "domain_add" || add[4] != "i-1" ||
		add[5] != fmt.Sprint(instanceID) || add[6] != "pihole1" || add[7] != "success" ||
		add[9] != `{"domain":"=HYPERLINK(\"http://evil\")"}` {
		t.Errorf("domain_add record: %q", add)
	}
	if carol := recs[1]; carol[2] != "'-carol" || carol[7] != "failure" || !strings.Contains(carol[9], `"error":"refused"`) {
		t.Errorf("a username starting with - isn't neutralised: %q", carol)
	}

	// The same filters as the list.
	res = c.do(http.MethodGet, "/api/v1/audit/export?"+url.Values{"user": {"alice"}, "action": {"domain_delete"}}.Encode(), nil)
	mustStatus(t, res, http.StatusOK)
	if recs := readCSV(t, res); len(recs) != 2 || recs[1][3] != "domain_delete" {
		t.Errorf("filtered export: %q", recs)
	}
	if res := c.do(http.MethodGet, "/api/v1/audit/export?result=maybe", nil); res.Code != http.StatusBadRequest {
		t.Errorf("bad filter: %d", res.Code)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":              "",
		"alice":         "alice",
		"=1+1":          "'=1+1",
		"+cmd":          "'+cmd",
		"-2":            "'-2",
		"@SUM(A1)":      "'@SUM(A1)",
		"\tx":           "'\tx",
		"\rx":           "'\rx",
		"a=b":           "a=b",
		"bad\xffbyte":   "bad�byte",
		"{\"a\":\"=\"}": "{\"a\":\"=\"}",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// writeAuditCSV reads in chunks and stops at maxAuditExport rows, asking for no more than it needs.
func TestWriteAuditCSVCap(t *testing.T) {
	const total = maxAuditExport + 1500
	rowsFrom := func(before int64, limit int) []db.AuditLog {
		var out []db.AuditLog
		for id := before - 1; id >= 1 && len(out) < limit; id-- {
			out = append(out, db.AuditLog{ID: id, At: 1, Username: "u", Action: "login", Result: "success", Detail: "{}"})
		}
		return out
	}
	var asked []int
	var buf bytes.Buffer
	err := writeAuditCSV(context.Background(), &buf, rowsFrom(total+1, auditExportChunk), func(before int64, limit int) ([]db.AuditLog, error) {
		asked = append(asked, limit)
		return rowsFrom(before, limit), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != maxAuditExport+1 {
		t.Errorf("%d rows, want %d and the header", len(recs)-1, maxAuditExport)
	}
	if last := recs[len(recs)-1][0]; last != fmt.Sprint(total-maxAuditExport+1) {
		t.Errorf("last row is %s: not the newest rows", last)
	}
	if len(asked) != maxAuditExport/auditExportChunk-1 {
		t.Errorf("read %d more chunks", len(asked))
	}

	// A short log stops after the first chunk; a read error ends the export with that error.
	asked = nil
	buf.Reset()
	if err := writeAuditCSV(context.Background(), &buf, rowsFrom(4, auditExportChunk), func(int64, int) ([]db.AuditLog, error) {
		asked = append(asked, 0)
		return nil, nil
	}); err != nil || len(asked) != 0 {
		t.Errorf("short log: %v, %d more reads", err, len(asked))
	}
	boom := errors.New("boom")
	if err := writeAuditCSV(context.Background(), &buf, rowsFrom(total, auditExportChunk), func(int64, int) ([]db.AuditLog, error) {
		return nil, boom
	}); !errors.Is(err, boom) {
		t.Errorf("read error: %v", err)
	}
}

// A deleted user's rows lose their user ID but keep the name, so they can still be found by it.
func TestAuditDeletedUser(t *testing.T) {
	e := newTestEnv(t)
	e.addRoleUser("bob", "bob-password-1", rbac.AuditView)
	gone := e.addRoleUser("gone", "gone-password-1", rbac.DomainsView)
	e.loggedIn("gone", "gone-password-1")
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error { return q.DeleteUser(ctx, gone) }); err != nil {
		t.Fatal(err)
	}
	l := decode[gen.AuditList](t, e.loggedIn("bob", "bob-password-1").do(http.MethodGet, auditQuery(url.Values{"user": {"gone"}}), nil))
	if len(l.Entries) != 1 || l.Entries[0].UserId != nil || l.Entries[0].Username != "gone" {
		t.Errorf("deleted user's login: %+v", l.Entries)
	}
}
