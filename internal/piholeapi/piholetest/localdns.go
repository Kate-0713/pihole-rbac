// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholetest

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// The local DNS part of the fake: the dns.hosts and dns.cnameRecords config arrays, as FTL's /api/config handles them
// (src/api/config.c, src/config/validator.c), and as a real Pi-hole (FTL v6.9) was seen to. A host record added is
// stored with runs of spaces collapsed; deletes match the whole string exactly; a duplicate add is a 400 "Item
// already present"; a delete of a missing string is a 404 with an empty JSON body; FTL's validator runs on the array
// after the change. An app-password session can only write with app_sudo on, which is off by default as in FTL. A
// cnameRecords write without ?restart=false restarts the fake: it drops the next RestartOutage connections, as a
// restarting FTL would, and its uptime starts again.

// SetLocalDNS replaces the dns.hosts and dns.cnameRecords arrays.
func (s *Server) SetLocalDNS(hosts, cnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts, s.cnames = slices.Clone(hosts), slices.Clone(cnames)
}

// LocalDNS returns the dns.hosts and dns.cnameRecords arrays.
func (s *Server) LocalDNS() (hosts, cnames []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.hosts), slices.Clone(s.cnames)
}

// SetAppSudo sets webserver.api.app_sudo. It is off until set, as in FTL.
func (s *Server) SetAppSudo(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appSudo = on
}

// SetConfigReadOnly sets misc.readOnly.
func (s *Server) SetConfigReadOnly(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readOnly = on
}

// LockLocalDNS marks dns.hosts and dns.cnameRecords as set by environment variables, which FTL's API can't change.
func (s *Server) LockLocalDNS(hosts, cnames bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostsEnv, s.cnamesEnv = hosts, cnames
}

// SetRestartOutage sets how many connections a restart drops before the fake answers again (default 2).
func (s *Server) SetRestartOutage(n int) { s.SetRestartPattern(n) }

// SetRestartPattern sets what a restart does to the connections after it, as counts that alternate between dropped
// and answered, starting with dropped: (1, 1, 3) drops one, answers one, then drops three, as a real Pi-hole (FTL v6.9)
// was seen doing, answering briefly after a restart and then going away again. Each run of answers after drops is a
// freshly started process, whose uptime starts from zero. After the last count every connection is answered.
func (s *Server) SetRestartPattern(counts ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restartPattern = slices.Clone(counts)
}

// Restarts is how many times a config change, or Restart DNS, restarted FTL.
func (s *Server) Restarts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restarts
}

// restart is called with s.mu held.
func (s *Server) restart() {
	s.restarts++
	s.pending = slices.Clone(s.restartPattern)
	s.droppingNow = true
	s.startedAt = time.Now()
}

// dropping reports whether the fake is restarting, and if so closes the connection without an answer.
func (s *Server) dropping(w http.ResponseWriter) bool {
	s.mu.Lock()
	for len(s.pending) > 0 && s.pending[0] == 0 { // a finished run: the next one starts
		s.pending = s.pending[1:]
		s.droppingNow = !s.droppingNow
		if !s.droppingNow {
			s.startedAt = time.Now() // answering again after drops: a freshly started process
		}
	}
	if len(s.pending) == 0 {
		s.droppingNow = true // the next pattern starts with drops
	}
	drop := len(s.pending) > 0 && s.droppingNow
	if len(s.pending) > 0 {
		s.pending[0]--
	}
	s.mu.Unlock()
	if !drop {
		return false
	}
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return true
		}
	}
	http.Error(w, "restarting", http.StatusServiceUnavailable)
	return true
}

// infoFTL answers GET /api/info/ftl with the parts the client reads. Called with s.mu held.
func (s *Server) infoFTL(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]any{"ftl": map[string]any{
		"pid": 4242, "uptime": float64(time.Since(s.startedAt).Milliseconds()),
	}})
}

// configLeaf is one item of a detailed config read.
func configLeaf(value any, envVar, restart bool) map[string]any {
	return map[string]any{
		"description": "", "allowed": nil, "type": "string array", "value": value, "default": []string{},
		"modified": true, "flags": map[string]bool{"restart_dnsmasq": restart, "session_reset": false, "env_var": envVar},
	}
}

// config answers /api/config/... for the items the app uses. seg starts with "config". Called with s.mu held.
func (s *Server) config(w http.ResponseWriter, r *http.Request, seg []string) {
	if r.Method == http.MethodGet {
		s.getConfig(w, r, seg)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete && !(r.Method == http.MethodPatch && len(seg) == 1) {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request method"))
		return
	}
	// api_config refuses app sessions without app_sudo before looking at the path.
	if !s.appSudo {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
			"key": "forbidden", "message": "Unable to change configuration (read-only)",
			"hint": "The current app session is not allowed to modify Pi-hole config settings (webserver.api.app_sudo is false)",
		}})
		return
	}
	if s.readOnly {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
			"key": "forbidden", "message": "The config is currently in read-only mode", "hint": nil,
		}})
		return
	}
	if r.Method == http.MethodPatch {
		s.patchConfig(w, r)
		return
	}
	dhcpHosts := len(seg) >= 4 && seg[1] == "dhcp" && seg[2] == "hosts"
	if !dhcpHosts && (len(seg) < 4 || seg[1] != "dns" || (seg[2] != "hosts" && seg[2] != "cnameRecords")) {
		writeJSON(w, http.StatusNotFound, map[string]any{"took": 0.001})
		return
	}
	item := seg[2]
	if dhcpHosts {
		item = "dhcp.hosts"
	}
	value := strings.Join(seg[3:], "/") // FTL takes everything after the item's path as the value
	if item == "hosts" && r.Method == http.MethodPut {
		// FTL v6.9 stores a host record with runs of spaces collapsed (seen on a real Pi-hole); a delete still
		// matches the string exactly.
		value = strings.Join(strings.FieldsFunc(value, func(r rune) bool { return r == ' ' }), " ")
	}
	if value == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"took": 0.001})
		return
	}
	arr, env, key := &s.hosts, s.hostsEnv, "dns.hosts"
	switch item {
	case "cnameRecords":
		arr, env, key = &s.cnames, s.cnamesEnv, "dns.cnameRecords"
	case "dhcp.hosts":
		arr, env, key = &s.dhcp.hosts, s.dhcp.env["hosts"], "dhcp.hosts"
	}
	if env {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"key": "bad_request", "message": "Config items set via environment variables cannot be changed via the API",
			"hint": key,
		}})
		return
	}
	i := slices.Index(*arr, value)
	if r.Method == http.MethodPut {
		if i >= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"key": "bad_request", "message": "Item already present", "hint": "Uniqueness of items is enforced",
			}})
			return
		}
		next := append(slices.Clone(*arr), value)
		var problem string
		switch item {
		case "hosts":
			problem = validateHosts(next)
		case "cnameRecords":
			problem = validateCNAMEs(next)
		default: // dhcp.hosts: FTL's validate_array_no_newline, and nothing more
			for i, v := range next {
				if strings.ContainsAny(v, "\r\n") {
					problem = fmt.Sprintf("[%d]: contains newline characters", i)
					break
				}
			}
		}
		if problem != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"key": "bad_request", "message": "Invalid value", "hint": key + problem,
			}})
			return
		}
		*arr = next
	} else {
		if i < 0 {
			writeJSON(w, http.StatusNotFound, map[string]any{"took": 0.001})
			return
		}
		*arr = slices.Delete(slices.Clone(*arr), i, i+1)
	}
	if (item == "cnameRecords" || item == "dhcp.hosts") && r.URL.Query().Get("restart") != "false" {
		s.restart()
	}
	if r.Method == http.MethodPut {
		writeJSON(w, http.StatusCreated, map[string]any{"took": 0.001})
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request, seg []string) {
	detailed := r.URL.Query().Get("detailed") == "true"
	path := strings.Join(seg[1:], "/")
	hosts, cnames := nonNilStrings(s.hosts), nonNilStrings(s.cnames)
	var body map[string]any
	switch path {
	case "dns":
		dns := map[string]any{"hosts": hosts, "cnameRecords": cnames, "domainNeeded": false}
		if detailed {
			dns = map[string]any{
				"hosts":        configLeaf(hosts, s.hostsEnv, false),
				"cnameRecords": configLeaf(cnames, s.cnamesEnv, true),
				"domainNeeded": configLeaf(false, false, true),
			}
		}
		body = map[string]any{"dns": dns}
	case "dns/hosts":
		body = map[string]any{"dns": map[string]any{"hosts": hosts}}
	case "dns/cnameRecords":
		body = map[string]any{"dns": map[string]any{"cnameRecords": cnames}}
	case "dhcp":
		body = map[string]any{"dhcp": s.dhcpConfig(detailed)}
	case "webserver/api/app_sudo":
		body = map[string]any{"webserver": map[string]any{"api": map[string]any{"app_sudo": s.appSudo}}}
	case "misc/readOnly":
		body = map[string]any{"misc": map[string]any{"readOnly": s.readOnly}}
	default:
		body = map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": body, "took": 0.001})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// validateHosts is FTL's validate_dns_hosts: no line breaks, an IPv4 or IPv6 address, then at least one valid
// hostname, up to a field starting with #. It returns "" or the problem.
func validateHosts(arr []string) string {
	for i, v := range arr {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Sprintf("[%d]: contains newline characters", i)
		}
		fields := strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == '\t' })
		if len(fields) == 0 {
			return fmt.Sprintf("[%d]: found no first element", i)
		}
		if a, err := netip.ParseAddr(fields[0]); err != nil || a.Zone() != "" {
			return fmt.Sprintf("[%d]: neither a valid IPv4 nor IPv6 address (%q)", i, fields[0])
		}
		hosts := 0
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			if !validDomain(f) {
				return fmt.Sprintf("[%d]: invalid hostname (%q)", i, f)
			}
			hosts++
		}
		if hosts == 0 {
			return fmt.Sprintf("[%d]: entry does not have at least one hostname", i)
		}
	}
	return ""
}

// validateCNAMEs is FTL's validate_dns_cnames: after cutting a comment, at least two comma-separated parts, none
// empty, and no line breaks. The names aren't checked as domains.
func validateCNAMEs(arr []string) string {
	for i, v := range arr {
		body := v
		for j, r := range v {
			if r == '#' && (j == 0 || v[j-1] == ' ' || v[j-1] == '\t') {
				body = v[:j]
				break
			}
		}
		parts := strings.Split(body, ",")
		for j, p := range parts {
			if p == "" {
				return fmt.Sprintf("[%d]: contains an empty string at position %d", i, j)
			}
		}
		if len(parts) < 2 {
			return fmt.Sprintf("[%d]: not a valid CNAME definition (too few elements)", i)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Sprintf("[%d]: contains newline characters", i)
		}
	}
	return ""
}

// validDomain is FTL's valid_domain without fqdn_only, for ASCII names: letters, digits, '-', '_' and dots, no empty
// label, labels of at most 63, at most 255 in all, and no hyphen at the start or end of the last label.
func validDomain(d string) bool {
	if d == "" || len(d) > 255 {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	labels := strings.Split(d, ".")
	for i, l := range labels {
		if len(l) > 63 || (l == "" && i < len(labels)-1) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return last == "" || (!strings.HasPrefix(last, "-") && !strings.HasSuffix(last, "-"))
}
