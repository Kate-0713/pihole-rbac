// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// fieldOf is the field a validation error names, or "" for any other error.
func fieldOf(err error) string {
	if e, ok := rbac.AsError(err); ok && e.Code == rbac.CodeValidation {
		f, _ := e.Details["field"].(string)
		return f
	}
	return ""
}

func TestQueryFilters(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		in    queryFilters
		want  piholeapi.QueryFilter
		field string // the refused field; "" when accepted
	}{
		{"nothing", queryFilters{}, piholeapi.QueryFilter{}, ""},
		{"everything", queryFilters{
			from: &t0, until: ptr(t0.Add(time.Hour)), domain: ptr("  ads.example "), client: ptr("fd00::1"),
			status: ptr("GRAVITY"), qtype: ptr("AAAA"), result: ptr("blocked"),
		}, piholeapi.QueryFilter{
			From: t0, Until: t0.Add(time.Hour), Domain: "ads.example", Client: "fd00::1", Status: "GRAVITY",
			Type: "AAAA", Upstream: piholeapi.UpstreamBlocked,
		}, ""},
		{"empty strings don't filter", queryFilters{domain: ptr(" "), status: ptr(""), result: ptr("")}, piholeapi.QueryFilter{}, ""},
		{"allowed", queryFilters{result: ptr("allowed")}, piholeapi.QueryFilter{Upstream: piholeapi.UpstreamPermitted}, ""},
		{"cached", queryFilters{result: ptr("cached")}, piholeapi.QueryFilter{Upstream: piholeapi.UpstreamCache}, ""},
		{"other type", queryFilters{qtype: ptr("OTHER")}, piholeapi.QueryFilter{Type: "OTHER"}, ""},
		{"until before from", queryFilters{from: &t0, until: ptr(t0.Add(-time.Second))}, piholeapi.QueryFilter{}, "until"},
		{"until equal to from", queryFilters{from: &t0, until: &t0}, piholeapi.QueryFilter{}, "until"},
		{"percent in domain", queryFilters{domain: ptr("a%")}, piholeapi.QueryFilter{}, "domain"},
		{"colon in domain", queryFilters{domain: ptr("a:b")}, piholeapi.QueryFilter{}, "domain"},
		{"long domain", queryFilters{domain: ptr(strings.Repeat("a", 256))}, piholeapi.QueryFilter{}, "domain"},
		{"newline in client", queryFilters{client: ptr("a\nb")}, piholeapi.QueryFilter{}, "client"},
		{"space in client", queryFilters{client: ptr("my pc")}, piholeapi.QueryFilter{}, "client"},
		{"lowercase status", queryFilters{status: ptr("gravity")}, piholeapi.QueryFilter{}, "status"},
		{"unknown status", queryFilters{status: ptr("BLOCKED")}, piholeapi.QueryFilter{}, "status"},
		{"TYPEnnn", queryFilters{qtype: ptr("TYPE65")}, piholeapi.QueryFilter{}, "type"},
		{"unknown result", queryFilters{result: ptr("denied")}, piholeapi.QueryFilter{}, "result"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.filter()
			if f := fieldOf(err); f != tt.field || (err != nil) != (tt.field != "") {
				t.Fatalf("err = %v (field %q), want field %q", err, f, tt.field)
			}
			if err == nil && got != tt.want {
				t.Errorf("filter %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestQueryPaging(t *testing.T) {
	tests := []struct {
		page, size *int
		wantPage   int
		wantSize   int
		field      string
	}{
		{nil, nil, 1, 100, ""},
		{ptr(7), ptr(25), 7, 25, ""},
		{ptr(maxQueryPageNumber), ptr(250), maxQueryPageNumber, 250, ""},
		{ptr(0), nil, 0, 0, "page"},
		{ptr(maxQueryPageNumber + 1), nil, 0, 0, "page"},
		{nil, ptr(1000), 0, 0, "page_size"},
		{nil, ptr(30), 0, 0, "page_size"},
	}
	for _, tt := range tests {
		p, n, err := queryPaging(tt.page, tt.size)
		if fieldOf(err) != tt.field || (err == nil && (p != tt.wantPage || n != tt.wantSize)) {
			t.Errorf("paging(%v, %v) = %d, %d, %v; want %d, %d, field %q", tt.page, tt.size, p, n, err, tt.wantPage, tt.wantSize, tt.field)
		}
	}
}

func TestQuerySnapshot(t *testing.T) {
	s := querySnapshot{3: {Cursor: ptr[int64](1234)}, 12: {Cursor: ptr[int64](99), Disk: true}, 5: {}, 7: {Cursor: ptr[int64](0)}}
	raw := s.encode()
	if !strings.HasPrefix(raw, "v1.") || strings.ContainsAny(raw, "+/=") {
		t.Errorf("encoded as %q", raw)
	}
	back, err := decodeSnapshot(raw)
	if err != nil || len(back) != 4 || !sameMember(back[3], s[3]) || !sameMember(back[12], s[12]) ||
		!sameMember(back[5], s[5]) || !sameMember(back[7], s[7]) {
		t.Fatalf("round trip: %v, %v", back, err)
	}
	enc := func(json string) string { return "v1." + base64.RawURLEncoding.EncodeToString([]byte(json)) }
	for name, bad := range map[string]string{
		"no prefix":       base64.RawURLEncoding.EncodeToString([]byte(`{"3":{"c":1}}`)),
		"other version":   "v2." + strings.TrimPrefix(enc(`{"3":{"c":1}}`), "v1."),
		"not base64":      "v1.!!!",
		"padded base64":   "v1." + base64.URLEncoding.EncodeToString([]byte(`{"3":{"c":1}}`)),
		"not JSON":        enc(`hello`),
		"null":            enc(`null`),
		"a list":          enc(`[1,2]`),
		"unknown field":   enc(`{"3":{"c":1,"x":2}}`),
		"negative cursor": enc(`{"3":{"c":-1}}`),
		"instance zero":   enc(`{"0":{"c":1}}`),
		"not an ID":       enc(`{"abc":{"c":1}}`),
		"trailing data":   enc(`{"3":{"c":1}}{}`),
		"too long":        "v1." + strings.Repeat("A", maxSnapshotBytes),
	} {
		if _, err := decodeSnapshot(bad); !errors.Is(err, errBadSnapshot) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := decodeSnapshot(enc(`{}`)); err != nil {
		t.Errorf("an empty snapshot (nothing answered) was refused: %v", err)
	}
}

// sameMember compares snapshot entries by value: no cursor, or the same one, and the same source.
func sameMember(a, b snapshotMember) bool {
	return a.Disk == b.Disk && (a.Cursor == nil) == (b.Cursor == nil) && (a.Cursor == nil || *a.Cursor == *b.Cursor)
}

func TestNeedsDisk(t *testing.T) {
	earliest := time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		from, until time.Time
		earliest    time.Time
		want        bool
	}{
		{"no time", time.Time{}, time.Time{}, earliest, false},
		{"no time, empty memory", time.Time{}, time.Time{}, time.Time{}, false},
		{"from inside memory", earliest.Add(time.Hour), time.Time{}, earliest, false},
		{"from at the oldest entry", earliest, time.Time{}, earliest, false},
		{"from before memory", earliest.Add(-time.Second), time.Time{}, earliest, true},
		{"until only", time.Time{}, earliest.Add(time.Hour), earliest, true},
		{"time with empty memory", earliest, time.Time{}, time.Time{}, true},
	}
	for _, tt := range tests {
		if got := needsDisk(piholeapi.QueryFilter{From: tt.from, Until: tt.until}, tt.earliest); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

// fakeReads records the reads readMember makes and answers them in turn.
type fakeReads struct {
	got     []piholeapi.QueryFilter
	answers []func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error)
}

func (r *fakeReads) read(_ context.Context, f piholeapi.QueryFilter) (*piholeapi.QueryPage, error) {
	r.got = append(r.got, f)
	if len(r.answers) == 0 {
		panic("unexpected read")
	}
	a := r.answers[0]
	r.answers = r.answers[1:]
	return a(f)
}

// queryAnswer is a page whose cursor is cursor (piholeapi.NoCursor for an empty log).
func queryAnswer(cursor int64, earliest time.Time) func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error) {
	return func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error) {
		return &piholeapi.QueryPage{Queries: []piholeapi.QueryLogEntry{}, Cursor: cursor, EarliestMemory: earliest}, nil
	}
}

func TestReadMember(t *testing.T) {
	earliest := time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC)
	rejected := func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error) {
		return nil, &piholeapi.RejectedError{Message: "Requested cursor is invalid"}
	}
	down := func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error) { return nil, piholeapi.ErrUnreachable }
	type read struct {
		disk   bool
		cursor int64 // -1 for none
	}
	tests := []struct {
		name    string
		f       piholeapi.QueryFilter
		prev    *snapshotMember
		answers []func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error)
		reads   []read
		want    snapshotMember
		wantErr bool
	}{
		{"memory", piholeapi.QueryFilter{}, nil, []func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(500, earliest)},
			[]read{{false, -1}}, snapshotMember{Cursor: ptr[int64](500)}, false},
		{"recent range stays in memory", piholeapi.QueryFilter{From: earliest.Add(time.Hour)}, nil,
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(500, earliest)},
			[]read{{false, -1}}, snapshotMember{Cursor: ptr[int64](500)}, false},
		{"older range read again from disk", piholeapi.QueryFilter{From: earliest.Add(-time.Hour)}, nil,
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(500, earliest), queryAnswer(510, earliest)},
			[]read{{false, -1}, {true, -1}}, snapshotMember{Cursor: ptr[int64](510), Disk: true}, false},
		{"no start goes to disk at once", piholeapi.QueryFilter{Until: earliest}, nil,
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(510, earliest)},
			[]read{{true, -1}}, snapshotMember{Cursor: ptr[int64](510), Disk: true}, false},
		{"snapshot keeps cursor and source", piholeapi.QueryFilter{From: earliest.Add(time.Hour)}, &snapshotMember{Cursor: ptr[int64](400), Disk: true},
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(400, earliest)},
			[]read{{true, 400}}, snapshotMember{Cursor: ptr[int64](400), Disk: true}, false},
		{"snapshot in memory isn't moved to disk", piholeapi.QueryFilter{From: earliest.Add(-time.Hour)}, &snapshotMember{Cursor: ptr[int64](400)},
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(400, earliest)},
			[]read{{false, 400}}, snapshotMember{Cursor: ptr[int64](400)}, false},
		{"refused cursor dropped", piholeapi.QueryFilter{}, &snapshotMember{Cursor: ptr[int64](9999)},
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){rejected, queryAnswer(20, earliest)},
			[]read{{false, 9999}, {false, -1}}, snapshotMember{Cursor: ptr[int64](20)}, false},
		{"refusal without a cursor is the member's failure", piholeapi.QueryFilter{}, nil,
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){rejected},
			[]read{{false, -1}}, snapshotMember{}, true},
		{"an empty log gives no cursor", piholeapi.QueryFilter{}, nil,
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(piholeapi.NoCursor, time.Time{})},
			[]read{{false, -1}}, snapshotMember{}, false},
		{"a cursor of 0 is kept and sent", piholeapi.QueryFilter{}, &snapshotMember{Cursor: ptr[int64](0)},
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){queryAnswer(0, earliest)},
			[]read{{false, 0}}, snapshotMember{Cursor: ptr[int64](0)}, false},
		{"down isn't retried", piholeapi.QueryFilter{}, &snapshotMember{Cursor: ptr[int64](9)},
			[]func(piholeapi.QueryFilter) (*piholeapi.QueryPage, error){down},
			[]read{{false, 9}}, snapshotMember{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReads{answers: tt.answers}
			tt.f.Start, tt.f.Length = 50, 25
			_, got, err := readMember(context.Background(), r.read, tt.f, tt.prev)
			if (err != nil) != tt.wantErr || !sameMember(got, tt.want) {
				t.Fatalf("got %+v, %v; want %+v, error %v", got, err, tt.want, tt.wantErr)
			}
			var reads []read
			for _, f := range r.got {
				c := int64(-1)
				if f.Cursor != nil {
					c = *f.Cursor
				}
				reads = append(reads, read{f.Disk, c})
				if f.Start != 50 || f.Length != 25 || f.From != tt.f.From || f.Until != tt.f.Until {
					t.Errorf("read lost the window or filters: %+v", f)
				}
			}
			if !slices.Equal(reads, tt.reads) {
				t.Errorf("reads %+v, want %+v", reads, tt.reads)
			}
		})
	}
}

func TestMergedPaging(t *testing.T) {
	q := func(id int, at float64, instance string) taggedQuery {
		return taggedQuery{piholeapi.QueryLogEntry{ID: id, Time: at}, instance}
	}
	merged := mergeQueries([][]taggedQuery{
		{q(30, 300, "alpha"), q(20, 200, "alpha"), q(10, 100, "alpha")},
		{q(7, 300, "beta"), q(6, 250, "beta")},
		{q(5, 300, "alpha2"), q(4, 300, "alpha2")},
	})
	var got []string
	for _, e := range merged {
		got = append(got, e.instance+"/"+strconv.Itoa(e.q.ID))
	}
	want := []string{"alpha/30", "alpha2/5", "alpha2/4", "beta/7", "beta/6", "alpha/20", "alpha/10"}
	if !slices.Equal(got, want) {
		t.Errorf("merged %v\nwant %v", got, want)
	}
	if p := pageOf(merged, 2, 3); len(p) != 3 || p[0].q.ID != 7 {
		t.Errorf("page 2 of 3: %v", p)
	}
	if p := pageOf(merged, 3, 3); len(p) != 1 || p[0].q.ID != 10 {
		t.Errorf("last page: %v", p)
	}
	if p := pageOf(merged, 9, 3); len(p) != 0 {
		t.Errorf("past the end: %v", p)
	}

	big := make([]taggedQuery, mergedQueryDepth+300)
	if p := pageOf(big, mergedQueryDepth/250, 250); len(p) != 250 {
		t.Errorf("the last page under the cap has %d entries", len(p))
	}
	if p := pageOf(big, mergedQueryDepth/250+1, 250); len(p) != 0 {
		t.Errorf("a page past the cap has %d entries", len(p))
	}

	windows := []struct {
		merged             bool
		page, size         int
		wantStart, wantLen int
	}{
		{false, 1, 100, 0, 100},
		{false, 4, 25, 75, 25},
		{true, 1, 100, 0, 100},
		{true, 3, 250, 0, 750},
		{true, 40, 250, 0, mergedQueryDepth},
	}
	for _, w := range windows {
		if s, n := queryWindow(w.merged, w.page, w.size); s != w.wantStart || n != w.wantLen {
			t.Errorf("window(%v, %d, %d) = %d, %d", w.merged, w.page, w.size, s, n)
		}
	}

	counts := []struct {
		merged      bool
		total, size int
		pages       int
		capped      bool
	}{
		{false, 0, 100, 0, false},
		{false, 101, 100, 2, false},
		{false, 1_000_000, 250, 4000, false},
		{true, 5000, 100, 50, false},
		{true, 5001, 100, 50, true},
		{true, 12345, 250, 20, true},
	}
	for _, c := range counts {
		if p, capped := pagesFor(c.merged, c.total, c.size); p != c.pages || capped != c.capped {
			t.Errorf("pagesFor(%v, %d, %d) = %d, %v", c.merged, c.total, c.size, p, capped)
		}
	}

	for want, disk := range map[string][]bool{"memory": nil, "disk": {true, true}, "mixed": {false, true}} {
		if got := sourceOf(disk); got != want {
			t.Errorf("sourceOf(%v) = %s, want %s", disk, got, want)
		}
	}
	if sourceOf([]bool{false}) != "memory" {
		t.Error("one member in memory")
	}
}
