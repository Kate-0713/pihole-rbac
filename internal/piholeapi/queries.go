// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// NoCursor is QueryPage.Cursor when Pi-hole has no entry to point at.
const NoCursor int64 = -1

// MaxQueryPage is the most query log entries one read returns. FTL caps a read at this many.
const MaxQueryPage = 10000

// The pseudo-upstreams Pi-hole's upstream filter accepts in place of a server.
const (
	UpstreamBlocked   = "blocklist" // every blocked status
	UpstreamPermitted = "permitted" // every status that was answered, cached or forwarded
	UpstreamCache     = "cache"     // answered from the cache
)

// QueryFilter selects and pages a query log read. A zero field doesn't filter.
type QueryFilter struct {
	From  time.Time // inclusive
	Until time.Time // exclusive
	// Domain matches a substring of the domain, ignoring case. Letters, digits, '.', '-', '_' and '*', which
	// matches any run of characters.
	Domain string
	// Client matches a substring of the client's address or name, ignoring case. As Domain, plus ':'.
	Client   string
	Status   string // one of FTL's status names
	Type     string // a record type name, or OTHER
	Upstream string // UpstreamBlocked, UpstreamPermitted or UpstreamCache

	Start  int    // entries to skip, counted after filtering
	Length int    // 1 to MaxQueryPage; 100 if zero
	Cursor *int64 // read only entries with this database ID or lower (IDs start at 0); nil for the newest
	Disk   bool   // read the long-term database instead of the in-memory log
}

// QueryPage is one read of the query log.
type QueryPage struct {
	Queries []QueryLogEntry // newest first
	// Cursor is the database ID of the newest entry this read could see. Sending it back keeps later reads to the
	// same entries while new queries arrive. NoCursor when Pi-hole has nothing to point at: it reports -1 while its
	// log is empty, and null at privacy level 3.
	Cursor int64
	// Total is how many entries the log read holds. Filtered is how many matched the filters, which is Total when
	// nothing but the cursor was given.
	Total, Filtered int
	// EarliestMemory is the time of the oldest entry in Pi-hole's in-memory log, or zero when it's empty.
	EarliestMemory time.Time
}

// ErrBadQueryFilter is returned, before anything is sent, for a filter value outside what QueryFilter allows. It
// matches ErrInvalidArgument too: handlers validate first, and this is the backstop.
var ErrBadQueryFilter = fmt.Errorf("%w: query log filter not allowed", ErrInvalidArgument)

// QueryLog reads one page of the query log, newest first, with the filters applied by Pi-hole. The client filter
// uses the column search Pi-hole's own web interface sends, which is the only one that matches an address or a
// name; it isn't in Pi-hole's API documentation.
func (c *Client) QueryLog(ctx context.Context, f QueryFilter) (*QueryPage, error) {
	v, err := f.values()
	if err != nil {
		return nil, err
	}
	var out struct {
		Queries           []QueryLogEntry `json:"queries"`
		Cursor            *int64          `json:"cursor"`
		RecordsTotal      int             `json:"recordsTotal"`
		RecordsFiltered   int             `json:"recordsFiltered"`
		EarliestTimestamp float64         `json:"earliest_timestamp"`
	}
	if err := c.doWith(ctx, c.slow, http.MethodGet, "/api/queries?"+v.Encode(), nil, &out); err != nil {
		return nil, err
	}
	page := &QueryPage{Queries: out.Queries, Cursor: NoCursor, Total: out.RecordsTotal, Filtered: out.RecordsFiltered}
	if page.Queries == nil {
		page.Queries = []QueryLogEntry{}
	}
	if out.Cursor != nil && *out.Cursor >= 0 {
		page.Cursor = *out.Cursor
	}
	if out.EarliestTimestamp > 0 {
		page.EarliestMemory = unixSeconds(out.EarliestTimestamp)
	}
	return page, nil
}

func (f QueryFilter) values() (url.Values, error) {
	v := url.Values{}
	length := f.Length
	if length == 0 {
		length = 100
	}
	if length < 1 || length > MaxQueryPage {
		return nil, fmt.Errorf("%w: length %d", ErrBadQueryFilter, f.Length)
	}
	v.Set("length", strconv.Itoa(length))
	if f.Start < 0 || (f.Cursor != nil && *f.Cursor < 0) {
		return nil, fmt.Errorf("%w: negative start or cursor", ErrBadQueryFilter)
	}
	if f.Start > 0 {
		v.Set("start", strconv.Itoa(f.Start))
	}
	if f.Cursor != nil {
		v.Set("cursor", strconv.FormatInt(*f.Cursor, 10))
	}
	if f.Disk {
		v.Set("disk", "true")
	}
	if !f.From.IsZero() {
		v.Set("from", unixString(f.From))
	}
	if !f.Until.IsZero() {
		v.Set("until", unixString(f.Until))
	}
	if f.Domain != "" {
		if !SearchTextOK(f.Domain, false) {
			return nil, fmt.Errorf("%w: domain", ErrBadQueryFilter)
		}
		v.Set("domain", "*"+strings.ToLower(f.Domain)+"*")
	}
	if f.Client != "" {
		if !SearchTextOK(f.Client, true) {
			return nil, fmt.Errorf("%w: client", ErrBadQueryFilter)
		}
		// FTL wraps the value in % itself, turns * into %, and escapes with a backslash, so only _ needs escaping
		// (% is never let through).
		v.Set("columns[4][data]", "client")
		v.Set("columns[4][search][value]", strings.ReplaceAll(strings.ToLower(f.Client), "_", `\_`))
	}
	if f.Status != "" {
		if !nameOK(f.Status) {
			return nil, fmt.Errorf("%w: status", ErrBadQueryFilter)
		}
		v.Set("status", f.Status)
	}
	if f.Type != "" {
		if !nameOK(f.Type) {
			return nil, fmt.Errorf("%w: type", ErrBadQueryFilter)
		}
		v.Set("type", f.Type)
	}
	switch f.Upstream {
	case "":
	case UpstreamBlocked, UpstreamPermitted, UpstreamCache:
		v.Set("upstream", f.Upstream)
	default:
		return nil, fmt.Errorf("%w: upstream", ErrBadQueryFilter)
	}
	return v, nil
}

// SearchTextOK reports whether s may be sent as a domain search (or, with client, a client search): 1 to 255
// letters, digits, '.', '-', '_' and '*', plus ':' for a client.
func SearchTextOK(s string, client bool) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '*':
		case r == ':' && client:
		default:
			return false
		}
	}
	return true
}

// nameOK reports whether s looks like one of FTL's status or type names. The API checks the exact lists; this
// only keeps anything else out of the request.
func nameOK(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// unixString gives t as Unix seconds with millisecond precision, as Pi-hole takes them.
func unixString(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', -1, 64)
}

func unixSeconds(f float64) time.Time {
	return time.UnixMilli(int64(math.Round(f * 1000))).UTC()
}
