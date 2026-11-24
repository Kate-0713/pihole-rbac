// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package contract_test

import (
	"context"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// The query log: filters applied by Pi-hole, paging counted after filtering, newest first, and a cursor that keeps
// later reads to the same entries while new queries arrive.

// TestQueryLogEmpty checks the read of an empty log. A real Pi-hole's log is read once, before any test runs, so on a
// freshly started Pi-hole the first read sees it empty. On one that had answered queries already it is skipped.
func TestQueryLogEmpty(t *testing.T) {
	tg := newTarget(t)
	page := live.firstQueryPage()
	if !tg.real() {
		var err error
		if page, err = tg.client(t).QueryLog(context.Background(), piholeapi.QueryFilter{}); err != nil {
			t.Fatal(err)
		}
	}
	if page.Total > 0 {
		t.Skipf("the query log held %d entries; this needs a Pi-hole that hadn't answered a query yet", page.Total)
	}
	// FTL reports a cursor of -1 for an empty log, since database IDs start at 0.
	if page.Cursor != piholeapi.NoCursor || len(page.Queries) != 0 || page.Filtered != 0 {
		t.Errorf("empty log = %+v, want no entries and NoCursor", page)
	}
}

func TestQueryLog(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	// Queries for a domain on the deny list are answered by Pi-hole itself, so no upstream server is needed.
	d := name(".example")
	tg.deny(t, c, d)
	for range 3 {
		tg.query(t, c, d, "DENYLIST")
	}

	read := func(t *testing.T, f piholeapi.QueryFilter) *piholeapi.QueryPage {
		t.Helper()
		f.Domain = d
		page, err := c.QueryLog(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}

	all := read(t, piholeapi.QueryFilter{})
	t.Run("filtered by domain, newest first", func(t *testing.T) {
		if all.Filtered != 3 || len(all.Queries) != 3 || all.Total < 3 {
			t.Fatalf("page = %d of %d filtered (%d total), want 3", len(all.Queries), all.Filtered, all.Total)
		}
		for i, q := range all.Queries {
			if q.Domain != d || q.Type != "A" || q.Status != "DENYLIST" || q.Client.IP != "127.0.0.1" {
				t.Errorf("entry %d = %+v, want an A query for %s from 127.0.0.1, DENYLIST", i, q, d)
			}
			if i > 0 && q.ID >= all.Queries[i-1].ID {
				t.Errorf("entry %d has ID %d after %d: not newest first", i, q.ID, all.Queries[i-1].ID)
			}
		}
		if all.Cursor < int64(all.Queries[0].ID) {
			t.Errorf("cursor = %d, want at least the newest entry's ID %d", all.Cursor, all.Queries[0].ID)
		}
		if all.EarliestMemory.IsZero() {
			t.Error("no earliest timestamp")
		}
	})

	t.Run("start and length page after filtering", func(t *testing.T) {
		page := read(t, piholeapi.QueryFilter{Start: 1, Length: 1})
		if len(page.Queries) != 1 || page.Queries[0].ID != all.Queries[1].ID || page.Filtered != 3 {
			t.Errorf("page = %+v, want only the second entry (ID %d) of 3", page, all.Queries[1].ID)
		}
	})

	t.Run("the cursor hides newer entries", func(t *testing.T) {
		cursor := all.Cursor
		tg.query(t, c, d, "DENYLIST")
		if page := read(t, piholeapi.QueryFilter{Cursor: &cursor}); page.Filtered != 3 || len(page.Queries) != 3 {
			t.Errorf("with the cursor: %d of %d, want the same 3 entries", len(page.Queries), page.Filtered)
		}
		if page := read(t, piholeapi.QueryFilter{}); page.Filtered != 4 {
			t.Errorf("without it: %d filtered, want 4", page.Filtered)
		}
	})

	tests := []struct {
		name string
		f    piholeapi.QueryFilter
		want int
	}{
		{"blocked pseudo-upstream", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamBlocked}, 4},
		{"permitted pseudo-upstream", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamPermitted}, 0},
		{"cache pseudo-upstream", piholeapi.QueryFilter{Upstream: piholeapi.UpstreamCache}, 0},
		{"status", piholeapi.QueryFilter{Status: "DENYLIST"}, 4},
		{"another status", piholeapi.QueryFilter{Status: "GRAVITY"}, 0},
		{"type", piholeapi.QueryFilter{Type: "A"}, 4},
		{"another type", piholeapi.QueryFilter{Type: "AAAA"}, 0},
		{"client address", piholeapi.QueryFilter{Client: "127.0.0.1"}, 4},
		{"client address part", piholeapi.QueryFilter{Client: "127.0.0"}, 4},
		{"another client", piholeapi.QueryFilter{Client: "192.0.2.99"}, 0},
	}
	for _, tt := range tests {
		t.Run("filter: "+tt.name, func(t *testing.T) {
			if page := read(t, tt.f); page.Filtered != tt.want || len(page.Queries) != tt.want {
				t.Errorf("%d of %d, want %d", len(page.Queries), page.Filtered, tt.want)
			}
		})
	}

	t.Run("a domain wildcard", func(t *testing.T) {
		page, err := c.QueryLog(ctx, piholeapi.QueryFilter{Domain: d[:len(prefix)+4] + "*.example"})
		if err != nil {
			t.Fatal(err)
		}
		if page.Filtered < 4 {
			t.Errorf("%d filtered, want at least 4", page.Filtered)
		}
	})
}
