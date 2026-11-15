// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholetest

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxQueryRows is FTL's cap on the entries one read returns.
const maxQueryRows = 10000

var (
	queryTypes = []string{"A", "AAAA", "ANY", "SRV", "SOA", "PTR", "TXT", "NAPTR", "MX", "DS", "RRSIG", "DNSKEY",
		"NS", "SVCB", "HTTPS"}
	queryStatuses = []string{"UNKNOWN", "GRAVITY", "FORWARDED", "CACHE", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP",
		"EXTERNAL_BLOCKED_NULL", "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "RETRIED",
		"RETRIED_DNSSEC", "IN_PROGRESS", "DBBUSY", "SPECIAL_DOMAIN", "CACHE_STALE", "EXTERNAL_BLOCKED_EDE15"}
	blockedStatuses = []string{"GRAVITY", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
		"EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "DBBUSY", "SPECIAL_DOMAIN",
		"EXTERNAL_BLOCKED_EDE15"}
	cachedStatuses    = []string{"CACHE", "CACHE_STALE"}
	permittedStatuses = []string{"FORWARDED", "CACHE", "RETRIED", "RETRIED_DNSSEC", "IN_PROGRESS", "CACHE_STALE"}
)

// listQueries answers GET /api/queries as FTL's api_queries does: entries newest first (by database ID), the
// filters ANDed, start counted after filtering, a cursor that hides newer entries, recordsFiltered equal to
// recordsTotal when nothing but the cursor was given, a cursor of -1 while the log is empty (database IDs start at 0),
// and the column search the web interface sends for clients.
// Called with s.mu held.
func (s *Server) listQueries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	disk := q.Get("disk") == "true"
	source := s.queries
	if disk {
		source = s.disk
	}
	maxID := -1
	for _, e := range slices.Concat(s.queries, s.disk) {
		maxID = max(maxID, e.ID)
	}

	var keep []func(Query) bool
	if v, ok := floatParam(q, "from"); ok {
		keep = append(keep, func(e Query) bool { return e.Time >= v })
	}
	if v, ok := floatParam(q, "until"); ok {
		keep = append(keep, func(e Query) bool { return e.Time < v })
	}
	if v := q.Get("domain"); v != "" {
		keep = append(keep, func(e Query) bool { return wildcard(v, e.Domain) })
	}
	if v := q.Get("client_ip"); v != "" {
		keep = append(keep, func(e Query) bool { return wildcard(v, e.Client.IP) })
	}
	if v := q.Get("client_name"); v != "" {
		keep = append(keep, func(e Query) bool { return wildcard(v, e.Client.Name) })
	}
	switch v := q.Get("upstream"); v {
	case "":
	case "blocklist":
		keep = append(keep, func(e Query) bool { return slices.Contains(blockedStatuses, e.Status) })
	case "permitted":
		keep = append(keep, func(e Query) bool { return slices.Contains(permittedStatuses, e.Status) })
	case "cache":
		keep = append(keep, func(e Query) bool { return slices.Contains(cachedStatuses, e.Status) })
	default:
		keep = append(keep, func(e Query) bool { return wildcard(v, e.Upstream) })
	}
	if v := q.Get("type"); v != "" {
		switch {
		case strings.EqualFold(v, "OTHER"):
			keep = append(keep, func(e Query) bool { return !slices.Contains(queryTypes, e.Type) })
		case slices.ContainsFunc(queryTypes, func(t string) bool { return strings.EqualFold(t, v) }):
			keep = append(keep, func(e Query) bool { return strings.EqualFold(e.Type, v) })
		default:
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Requested type is invalid"))
			return
		}
	}
	if v := q.Get("status"); v != "" {
		if !slices.Contains(queryStatuses, strings.ToUpper(v)) {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Requested status is invalid"))
			return
		}
		keep = append(keep, func(e Query) bool { return strings.EqualFold(e.Status, v) })
	}
	// FTL looks the column search up by its escaped name, so the brackets must arrive as %5B and %5D.
	if strings.Contains(r.URL.RawQuery, "columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=") {
		if v, data := q.Get("columns[4][search][value]"), q.Get("columns[4][data]"); v != "" &&
			(strings.EqualFold(data, "client") || strings.EqualFold(data, "client.ip")) {
			pat := strings.ReplaceAll(v, "*", "%")
			if !strings.HasSuffix(pat, "%") {
				pat += "%"
			}
			if !strings.HasPrefix(pat, "%") {
				pat = "%" + pat
			}
			keep = append(keep, func(e Query) bool {
				return like(pat, e.Client.IP, true) || (e.Client.Name != "" && like(pat, e.Client.Name, true))
			})
		}
	}
	filtering := len(keep) > 0

	cursor := maxID
	if raw := q.Get("cursor"); raw != "" {
		c, err := strconv.ParseUint(raw, 10, 63)
		if err != nil || int(c) > maxID {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Requested cursor is invalid"))
			return
		}
		cursor = int(c)
		keep = append(keep, func(e Query) bool { return e.ID <= cursor })
	}
	length := 100
	if v, err := strconv.Atoi(q.Get("length")); err == nil {
		length = v
	}
	if length <= 0 || length > maxQueryRows {
		length = maxQueryRows
	}
	start, _ := strconv.Atoi(q.Get("start"))

	rows := slices.Clone(source)
	slices.SortStableFunc(rows, func(a, b Query) int { return b.ID - a.ID })
	out := []Query{}
	matched := 0
	for _, e := range rows {
		if !all(keep, e) {
			continue
		}
		matched++
		if matched <= start || len(out) >= length {
			continue
		}
		out = append(out, e)
	}
	filtered := len(source)
	if filtering {
		filtered = matched
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queries": out, "cursor": cursor, "recordsTotal": len(source), "recordsFiltered": filtered, "draw": 0,
		"earliest_timestamp": earliest(s.queries), "earliest_timestamp_disk": earliest(s.disk),
	})
}

func all(keep []func(Query) bool, e Query) bool {
	for _, k := range keep {
		if !k(e) {
			return false
		}
	}
	return true
}

func earliest(qs []Query) float64 {
	if len(qs) == 0 {
		return 0
	}
	t := qs[0].Time
	for _, e := range qs {
		t = min(t, e.Time)
	}
	return t
}

func floatParam(q map[string][]string, key string) (float64, bool) {
	if len(q[key]) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(q[key][0], 64)
	return v, err == nil
}

// wildcard is FTL's filter match: equality, or a LIKE (without an escape character) when the value has a '*'.
func wildcard(filter, value string) bool {
	if !strings.Contains(filter, "*") {
		return filter == value
	}
	return like(strings.ReplaceAll(filter, "*", "%"), value, false)
}

// like is SQLite's LIKE: '%' matches any run of characters, '_' any one, ASCII letters ignore case, and with
// escape a backslash makes the next character literal.
func like(pattern, s string, escape bool) bool {
	for pattern != "" {
		p, n := utf8.DecodeRuneInString(pattern)
		pattern = pattern[n:]
		switch {
		case p == '%':
			for i := 0; ; {
				if like(pattern, s[i:], escape) {
					return true
				}
				if i >= len(s) {
					return false
				}
				_, m := utf8.DecodeRuneInString(s[i:])
				i += m
			}
		case p == '_':
			if s == "" {
				return false
			}
			_, m := utf8.DecodeRuneInString(s)
			s = s[m:]
		default:
			if p == '\\' && escape && pattern != "" {
				p, n = utf8.DecodeRuneInString(pattern)
				pattern = pattern[n:]
			}
			c, m := utf8.DecodeRuneInString(s)
			if s == "" || !foldASCII(p, c) {
				return false
			}
			s = s[m:]
		}
	}
	return s == ""
}

func foldASCII(a, b rune) bool {
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}
	return lower(a) == lower(b)
}
