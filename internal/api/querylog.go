// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// The query log's paging. A mirrored group's merged log needs page × page size entries from every member, so it is
// paged no deeper than mergedQueryDepth merged entries; reading one member alone has no such limit.
const (
	defaultQueryPageSize = 100
	maxQueryPageNumber   = 1_000_000
	mergedQueryDepth     = 5000
)

var queryPageSizes = []int{25, 50, 100, 250}

// The status and type names the query log filters accept: FTL's (Pi-hole v6).
var (
	queryStatuses = []string{"UNKNOWN", "GRAVITY", "FORWARDED", "CACHE", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP",
		"EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "RETRIED",
		"RETRIED_DNSSEC", "IN_PROGRESS", "DBBUSY", "SPECIAL_DOMAIN", "CACHE_STALE", "EXTERNAL_BLOCKED_EDE15"}
	queryTypes = []string{"A", "AAAA", "ANY", "SRV", "SOA", "PTR", "TXT", "NAPTR", "MX", "DS", "RRSIG", "DNSKEY", "NS",
		"SVCB", "HTTPS", "OTHER"}
	queryResults = map[string]string{
		"blocked": piholeapi.UpstreamBlocked,
		"allowed": piholeapi.UpstreamPermitted,
		"cached":  piholeapi.UpstreamCache,
	}
)

// queryFilters is a query log request's filters, as strings from the request; nil pointers aren't given.
type queryFilters struct {
	from, until                           *time.Time
	domain, client, status, qtype, result *string
}

// filter checks the filters and turns them into what the Pi-hole client sends. Every value is checked against a fixed
// list or character set here, so nothing unexpected reaches a Pi-hole.
func (q queryFilters) filter() (piholeapi.QueryFilter, error) {
	var f piholeapi.QueryFilter
	if q.from != nil {
		f.From = *q.from
	}
	if q.until != nil {
		f.Until = *q.until
	}
	if !f.From.IsZero() && !f.Until.IsZero() && !f.Until.After(f.From) {
		return f, invalid("until", "The end of the time range must be after its start.")
	}
	text := func(field string, v *string, client bool) (string, error) {
		if v == nil {
			return "", nil
		}
		s := strings.TrimSpace(*v)
		if s != "" && !piholeapi.SearchTextOK(s, client) {
			allowed := "letters, digits, dots, hyphens, underscores and *"
			if client {
				allowed = "letters, digits, dots, colons, hyphens, underscores and *"
			}
			return "", invalid(field, "The %s filter can only hold %s, up to 255 characters.", field, allowed)
		}
		return s, nil
	}
	var err error
	if f.Domain, err = text("domain", q.domain, false); err != nil {
		return f, err
	}
	if f.Client, err = text("client", q.client, true); err != nil {
		return f, err
	}
	if q.status != nil && *q.status != "" {
		if !slices.Contains(queryStatuses, *q.status) {
			return f, invalid("status", "%q isn't a query status.", *q.status)
		}
		f.Status = *q.status
	}
	if q.qtype != nil && *q.qtype != "" {
		if !slices.Contains(queryTypes, *q.qtype) {
			return f, invalid("type", "%q isn't a record type the query log can filter by.", *q.qtype)
		}
		f.Type = *q.qtype
	}
	if q.result != nil && *q.result != "" {
		up, ok := queryResults[*q.result]
		if !ok {
			return f, invalid("result", "The result must be blocked, allowed or cached.")
		}
		f.Upstream = up
	}
	return f, nil
}

// queryPaging checks the page and page size, defaulting them.
func queryPaging(page, size *int) (int, int, error) {
	p, n := 1, defaultQueryPageSize
	if page != nil {
		p = *page
		if p < 1 || p > maxQueryPageNumber {
			return 0, 0, invalid("page", "The page must be between 1 and %d.", maxQueryPageNumber)
		}
	}
	if size != nil {
		n = *size
		if !slices.Contains(queryPageSizes, n) {
			return 0, 0, invalid("page_size", "The page size must be 25, 50, 100 or 250.")
		}
	}
	return p, n, nil
}

// querySnapshot keeps a search's later pages to the entries its first page could see: per instance ID, the newest
// database ID read (none for a member whose log was empty, so it is read from the newest next time) and whether the
// member was read from disk. It is a convenience, not a secret, and can only narrow
// a read: a cursor hides newer entries, and disk is a choice any reader can make by asking for an older range.
type querySnapshot map[int64]snapshotMember

type snapshotMember struct {
	Cursor *int64 `json:"c,omitempty"`
	Disk   bool   `json:"d,omitempty"`
}

const (
	snapshotPrefix   = "v1."
	maxSnapshotBytes = 2048
)

var errBadSnapshot = errors.New("bad snapshot")

func (s querySnapshot) encode() string {
	b, _ := json.Marshal(s) // a map of int64 to a plain struct always encodes
	return snapshotPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func decodeSnapshot(raw string) (querySnapshot, error) {
	rest, ok := strings.CutPrefix(raw, snapshotPrefix)
	if !ok || len(raw) > maxSnapshotBytes {
		return nil, errBadSnapshot
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return nil, errBadSnapshot
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var s querySnapshot
	if err := dec.Decode(&s); err != nil || dec.More() || s == nil {
		return nil, errBadSnapshot
	}
	for id, m := range s {
		if id < 1 || (m.Cursor != nil && *m.Cursor < 0) {
			return nil, errBadSnapshot
		}
	}
	return s, nil
}

// needsDisk reports whether a read whose in-memory log starts at earliest (zero when it is empty) has to go to
// Pi-hole's long-term database: a time was given, and the range starts before the in-memory log or has no start.
func needsDisk(f piholeapi.QueryFilter, earliest time.Time) bool {
	switch {
	case f.From.IsZero() && f.Until.IsZero():
		return false
	case f.From.IsZero(), earliest.IsZero():
		return true
	}
	return f.From.Before(earliest)
}

// queryReader is the one Pi-hole call reading a member needs, so the reading rules can be tested without a pool.
type queryReader func(ctx context.Context, f piholeapi.QueryFilter) (*piholeapi.QueryPage, error)

// readMember reads one member's page. With a snapshot entry it uses that cursor and source. Without one, a range
// with no start goes to disk at once; anything else is read from memory first, and again from disk when the answer
// shows the range starts before the in-memory log. A cursor Pi-hole refuses (its log was flushed since) is dropped
// and the read made again, so an old snapshot can't break the page.
func readMember(ctx context.Context, read queryReader, f piholeapi.QueryFilter, prev *snapshotMember) (*piholeapi.QueryPage, snapshotMember, error) {
	switch {
	case prev != nil:
		f.Cursor, f.Disk = prev.Cursor, prev.Disk
	case f.From.IsZero() && !f.Until.IsZero():
		f.Disk = true
	}
	page, err := read(ctx, f)
	if err != nil && f.Cursor != nil && errors.Is(err, piholeapi.ErrRejected) {
		f.Cursor = nil
		page, err = read(ctx, f)
	}
	if err == nil && prev == nil && !f.Disk && needsDisk(f, page.EarliestMemory) {
		f.Disk = true
		page, err = read(ctx, f)
	}
	if err != nil {
		return nil, snapshotMember{}, err
	}
	seen := snapshotMember{Disk: f.Disk}
	if page.Cursor >= 0 {
		seen.Cursor = &page.Cursor
	}
	return page, seen, nil
}

// taggedQuery is a query log entry with the instance it came from.
type taggedQuery struct {
	q        piholeapi.QueryLogEntry
	instance string
}

// mergeQueries merges members' entries newest first; ties go by instance name, then newest database ID, so a page
// boundary always falls in the same place.
func mergeQueries(lists [][]taggedQuery) []taggedQuery {
	merged := slices.Concat(lists...)
	slices.SortStableFunc(merged, func(a, b taggedQuery) int {
		return cmp.Or(cmp.Compare(b.q.Time, a.q.Time), cmp.Compare(a.instance, b.instance), cmp.Compare(b.q.ID, a.q.ID))
	})
	return merged
}

// queryWindow is how a page is read from each member: from the start for the merged view, which needs everything
// before the page too, or just the page for one member.
func queryWindow(merged bool, page, size int) (start, length int) {
	if merged {
		return 0, min(page*size, mergedQueryDepth)
	}
	return (page - 1) * size, size
}

// pageOf cuts page from merged entries, never past the depth cap.
func pageOf(merged []taggedQuery, page, size int) []taggedQuery {
	lo := min((page-1)*size, len(merged), mergedQueryDepth)
	hi := min(page*size, len(merged), mergedQueryDepth)
	return merged[lo:hi]
}

// pagesFor gives how many pages can be reached and whether a merged log has more entries than that.
func pagesFor(merged bool, total, size int) (pages int, capped bool) {
	reach := total
	if merged && total > mergedQueryDepth {
		reach, capped = mergedQueryDepth, true
	}
	return (reach + size - 1) / size, capped
}

// sourceOf names where the members that answered were read: memory, disk, or mixed.
func sourceOf(disk []bool) string {
	switch {
	case len(disk) == 0 || !slices.Contains(disk, true):
		return "memory"
	case !slices.Contains(disk, false):
		return "disk"
	}
	return "mixed"
}

// asString and asInt read optional parameters whatever named type the generated code gives them.
func asString[T ~string](p *T) *string {
	if p == nil {
		return nil
	}
	s := string(*p)
	return &s
}

func asInt[T ~int](p *T) *int {
	if p == nil {
		return nil
	}
	n := int(*p)
	return &n
}
