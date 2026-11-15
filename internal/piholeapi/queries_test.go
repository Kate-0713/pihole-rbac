// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

func TestQueryLogParameters(t *testing.T) {
	from := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		f    piholeapi.QueryFilter
		want string
	}{
		{"defaults", piholeapi.QueryFilter{}, "length=100"},
		{"paging", piholeapi.QueryFilter{Start: 200, Length: 100, Cursor: ptr[int64](9876)},
			"cursor=9876&length=100&start=200"},
		{"a cursor of 0 is a cursor", piholeapi.QueryFilter{Cursor: ptr[int64](0)}, "cursor=0&length=100"},
		{"time and disk", piholeapi.QueryFilter{From: from, Until: from.Add(90*time.Minute + 250*time.Millisecond), Disk: true},
			"disk=true&from=1794556800&length=100&until=1794562200.25"},
		{"domain is a lowercased substring", piholeapi.QueryFilter{Domain: "Ads.Example"},
			"domain=%2Aads.example%2A&length=100"},
		{"client uses the column search, with _ escaped", piholeapi.QueryFilter{Client: "My_PC"},
			"columns%5B4%5D%5Bdata%5D=client&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=my%5C_pc&length=100"},
		{"client address", piholeapi.QueryFilter{Client: "fd00::1"},
			"columns%5B4%5D%5Bdata%5D=client&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=fd00%3A%3A1&length=100"},
		{"names and upstream", piholeapi.QueryFilter{Status: "GRAVITY", Type: "AAAA", Upstream: piholeapi.UpstreamBlocked},
			"length=100&status=GRAVITY&type=AAAA&upstream=blocklist"},
		{"largest page", piholeapi.QueryFilter{Length: piholeapi.MaxQueryPage}, "length=10000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			var got string
			ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
				got = r.URL.EscapedPath() + "?" + r.URL.RawQuery
				_, _ = w.Write([]byte(`{"queries":[],"cursor":null,"recordsTotal":0,"recordsFiltered":0}`))
				return true
			})
			page, err := newClient(t, ph.URL).QueryLog(context.Background(), tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if want := "/api/queries?" + tt.want; got != want {
				t.Errorf("sent %s\nwant %s", got, want)
			}
			if page.Queries == nil || page.Cursor != piholeapi.NoCursor || !page.EarliestMemory.IsZero() {
				t.Errorf("empty answer read as %+v", page)
			}
		})
	}
}

func TestQueryLogRefusesBadFilters(t *testing.T) {
	tests := []struct {
		name string
		f    piholeapi.QueryFilter
	}{
		{"percent in domain", piholeapi.QueryFilter{Domain: "a%b"}},
		{"space in domain", piholeapi.QueryFilter{Domain: "a b"}},
		{"colon in domain", piholeapi.QueryFilter{Domain: "fd00::1"}},
		{"backslash in client", piholeapi.QueryFilter{Client: `a\b`}},
		{"newline in client", piholeapi.QueryFilter{Client: "a\nb"}},
		{"non-ASCII client", piholeapi.QueryFilter{Client: "café"}},
		{"long domain", piholeapi.QueryFilter{Domain: string(make([]byte, 256))}},
		{"lowercase status", piholeapi.QueryFilter{Status: "gravity"}},
		{"status with &", piholeapi.QueryFilter{Status: "GRAVITY&disk=true"}},
		{"type with space", piholeapi.QueryFilter{Type: "A AAA"}},
		{"real upstream", piholeapi.QueryFilter{Upstream: "8.8.8.8"}},
		{"length too large", piholeapi.QueryFilter{Length: piholeapi.MaxQueryPage + 1}},
		{"negative length", piholeapi.QueryFilter{Length: -1}},
		{"negative start", piholeapi.QueryFilter{Start: -1}},
		{"negative cursor", piholeapi.QueryFilter{Cursor: ptr[int64](-5)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			c := newClient(t, ph.URL)
			before := len(ph.Requests())
			_, err := c.QueryLog(context.Background(), tt.f)
			if !errors.Is(err, piholeapi.ErrBadQueryFilter) {
				t.Fatalf("err = %v, want ErrBadQueryFilter", err)
			}
			if n := len(ph.Requests()); n != before {
				t.Errorf("%d requests sent", n-before)
			}
		})
	}
}

// queryLogFixture is ten queries a minute apart, IDs 101 to 110, newest first, from two clients.
func queryLogFixture() []piholetest.Query {
	base := float64(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC).Unix())
	var qs []piholetest.Query
	for i := 10; i >= 1; i-- {
		q := piholetest.Query{ID: 100 + i, Time: base + float64(i*60), Type: "A", Domain: "site.example",
			Status: "FORWARDED", Upstream: "1.1.1.1#53"}
		q.Client.IP, q.Client.Name = "10.0.0.5", "laptop_one.lan"
		if i%2 == 0 {
			q.Client.IP, q.Client.Name = "10.0.0.7", "phone.lan"
		}
		switch i {
		case 3, 6:
			q.Domain, q.Status = "ads.tracker.example", "GRAVITY"
		case 9:
			q.Type, q.Status = "AAAA", "CACHE"
		}
		qs = append(qs, q)
	}
	return qs
}

func TestQueryLogAgainstFake(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	ph.SetQueries(queryLogFixture())
	old := piholetest.Query{ID: 50, Time: float64(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix()), Type: "A",
		Domain: "old.example", Status: "FORWARDED"}
	ph.SetDiskQueries(append(queryLogFixture(), old))
	c := newClient(t, ph.URL)

	ids := func(p *piholeapi.QueryPage) []int {
		var out []int
		for _, q := range p.Queries {
			out = append(out, q.ID)
		}
		return out
	}
	at := func(min int) time.Time { return time.Date(2026, 11, 14, 12, min, 0, 0, time.UTC) }
	tests := []struct {
		name           string
		f              piholeapi.QueryFilter
		ids            []int
		total, matched int
	}{
		{"newest first", piholeapi.QueryFilter{Length: 3}, []int{110, 109, 108}, 10, 10},
		{"second page", piholeapi.QueryFilter{Start: 3, Length: 3}, []int{107, 106, 105}, 10, 10},
		{"past the end", piholeapi.QueryFilter{Start: 20, Length: 3}, nil, 10, 10},
		{"cursor hides newer", piholeapi.QueryFilter{Cursor: ptr[int64](105), Length: 2}, []int{105, 104}, 10, 10},
		{"domain substring", piholeapi.QueryFilter{Domain: "TRACKER"}, []int{106, 103}, 10, 2},
		{"client by name, _ literal", piholeapi.QueryFilter{Client: "top_on"}, []int{109, 107, 105, 103, 101}, 10, 5},
		{"_ doesn't match any character", piholeapi.QueryFilter{Client: "ph_ne"}, nil, 10, 0},
		{"client by address", piholeapi.QueryFilter{Client: "0.0.7"}, []int{110, 108, 106, 104, 102}, 10, 5},
		{"client wildcard", piholeapi.QueryFilter{Client: "pho*lan"}, []int{110, 108, 106, 104, 102}, 10, 5},
		{"time range", piholeapi.QueryFilter{From: at(3), Until: at(5)}, []int{104, 103}, 10, 2},
		{"blocked", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamBlocked}, []int{106, 103}, 10, 2},
		{"cached", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamCache}, []int{109}, 10, 1},
		{"allowed", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamPermitted, Length: 2}, []int{110, 109}, 10, 8},
		{"status and type", piholeapi.QueryFilter{Status: "CACHE", Type: "AAAA"}, []int{109}, 10, 1},
		{"filtered paging", piholeapi.QueryFilter{Client: "phone", Start: 2, Length: 2, Cursor: ptr[int64](108)}, []int{104, 102}, 10, 4},
		{"disk", piholeapi.QueryFilter{Disk: true, Domain: "old"}, []int{50}, 11, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := c.QueryLog(ctx, tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(p); !slices.Equal(got, tt.ids) {
				t.Errorf("ids %v, want %v", got, tt.ids)
			}
			if p.Total != tt.total || p.Filtered != tt.matched {
				t.Errorf("total %d, filtered %d; want %d, %d", p.Total, p.Filtered, tt.total, tt.matched)
			}
			wantCursor := int64(110)
			if tt.f.Cursor != nil {
				wantCursor = *tt.f.Cursor
			}
			if p.Cursor != wantCursor {
				t.Errorf("cursor %d, want %d", p.Cursor, wantCursor)
			}
			if !p.EarliestMemory.Equal(at(1)) {
				t.Errorf("earliest %v, want %v", p.EarliestMemory, at(1))
			}
		})
	}

	_, err := c.QueryLog(ctx, piholeapi.QueryFilter{Cursor: ptr[int64](111)})
	var re *piholeapi.RejectedError
	if !errors.As(err, &re) {
		t.Errorf("cursor past the newest: err = %v, want Pi-hole's 400", err)
	}
}

// TestQueryLogEmpty: a Pi-hole whose log is empty reports a cursor of -1 (FTL's IDs start at 0), which the client
// gives as NoCursor rather than as a position, as it does for the null sent at privacy level 3.
func TestQueryLogEmpty(t *testing.T) {
	for name, body := range map[string]string{
		"empty log": `{"queries":[],"cursor":-1,"recordsTotal":0,"recordsFiltered":0,"earliest_timestamp":0}`,
		"privacy 3": `{"queries":[],"cursor":null,"recordsTotal":0,"recordsFiltered":0}`,
	} {
		ph := piholetest.New(t, password)
		ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte(body))
			return true
		})
		p, err := newClient(t, ph.URL).QueryLog(context.Background(), piholeapi.QueryFilter{})
		if err != nil || p.Cursor != piholeapi.NoCursor {
			t.Errorf("%s: cursor %v, %v", name, p, err)
		}
	}
	// The fake does the same.
	ph := piholetest.New(t, password)
	p, err := newClient(t, ph.URL).QueryLog(context.Background(), piholeapi.QueryFilter{})
	if err != nil || p.Cursor != piholeapi.NoCursor {
		t.Errorf("the fake's empty log: %+v, %v", p, err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestQueryLogTimeout(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		time.Sleep(300 * time.Millisecond)
		return false
	})
	c := newClient(t, ph.URL, func(o *piholeapi.Options) {
		o.Timeout = 150 * time.Millisecond
		o.QueryTimeout = 2 * time.Second
	})
	if _, err := c.QueryLog(ctx, piholeapi.QueryFilter{}); err != nil {
		t.Errorf("query log read under its own timeout: %v", err)
	}
	if _, err := c.ListGroups(ctx); err == nil {
		t.Error("an ordinary read outlived the ordinary timeout")
	}
}
