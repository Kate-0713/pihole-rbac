// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholetest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// The DHCP part of the fake, as FTL's /api/dhcp and /api/config handle it (src/api/dhcp.c, src/api/config.c,
// src/config/config.c, src/config/dnsmasq_config.c):
//
//   - Leases are the lease file's lines, listed whether or not DHCP is on. A delete needs DHCP on (400 "DHCP is not
//     enabled"), is 404 for an address with no lease, and 503 when the resolver is busy (SetLeaseBusy). It doesn't
//     restart anything, and the fake doesn't ask for app_sudo.
//   - Every dhcp config item restarts FTL, so a PATCH that changes one, or a dhcp.hosts add or delete, restarts the
//     fake unless ?restart=false. A PATCH value equal to the current one is skipped, as in FTL: it isn't validated,
//     doesn't restart, and isn't refused when the item is set by an environment variable.
//   - A PATCH that changes something is checked as a whole, as FTL does when it writes dnsmasq's config: the
//     validators on the items that changed (an address is IPv4 or empty, a netmask is contiguous, a lease time has no
//     line break), then, with DHCP on, the start, end and router set, none of them the network or broadcast address,
//     the start not after the end, and the router outside the range. A refusal is a 400 and nothing is applied.
//   - dhcp.hosts is only checked for line breaks, as FTL does. The fake doesn't run dnsmasq, so a static lease
//     dnsmasq would refuse is accepted here: that is for the checks on a real Pi-hole.

// DHCPSettings are the dhcp config items other than dhcp.hosts, as the fake holds them.
type DHCPSettings struct {
	Active               bool   `json:"active"`
	Start                string `json:"start"`
	End                  string `json:"end"`
	Router               string `json:"router"`
	Netmask              string `json:"netmask"`
	LeaseTime            string `json:"leaseTime"`
	IPv6                 bool   `json:"ipv6"`
	MultiDNS             bool   `json:"multiDNS"`
	RapidCommit          bool   `json:"rapidCommit"`
	Logging              bool   `json:"logging"`
	IgnoreUnknownClients bool   `json:"ignoreUnknownClients"`
}

// DHCPLease is a lease as FTL lists it. Name and ClientID are "*" when there is none, as in dnsmasq's lease file.
type DHCPLease struct {
	Expires  int64  `json:"expires"`
	HWAddr   string `json:"hwaddr"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	ClientID string `json:"clientid"`
}

type dhcpState struct {
	settings DHCPSettings
	hosts    []string
	env      map[string]bool // config items, by key under dhcp, set by environment variables
	leases   []DHCPLease
	busy     bool
	deletes  int // lease deletes that reached the resolver
}

// SetDHCP replaces the DHCP settings.
func (s *Server) SetDHCP(d DHCPSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.settings = d
}

// DHCP returns the DHCP settings.
func (s *Server) DHCP() DHCPSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dhcp.settings
}

// SetStaticLeases replaces the dhcp.hosts array.
func (s *Server) SetStaticLeases(hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.hosts = slices.Clone(hosts)
}

// StaticLeases returns the dhcp.hosts array.
func (s *Server) StaticLeases() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.dhcp.hosts)
}

// SetLeases replaces the lease file's leases.
func (s *Server) SetLeases(l []DHCPLease) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.leases = slices.Clone(l)
}

// Leases returns the lease file's leases.
func (s *Server) Leases() []DHCPLease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.dhcp.leases)
}

// LeaseDeletes is how many lease deletes reached the resolver.
func (s *Server) LeaseDeletes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dhcp.deletes
}

// SetLeaseBusy makes lease deletes time out waiting for the resolver, as FTL does when it is too busy: a 503.
func (s *Server) SetLeaseBusy(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.busy = on
}

// LockDHCP marks dhcp config items, by their key under dhcp ("start", "hosts"), as set by environment variables,
// which FTL's API can't change.
func (s *Server) LockDHCP(keys ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dhcp.env = map[string]bool{}
	for _, k := range keys {
		s.dhcp.env[k] = true
	}
}

// dhcpLeases answers /api/dhcp/leases. Called with s.mu held.
func (s *Server) dhcpLeases(w http.ResponseWriter, r *http.Request, seg []string) {
	switch {
	case r.Method == http.MethodGet && len(seg) == 2:
		leases := s.dhcp.leases
		if leases == nil {
			leases = []DHCPLease{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"leases": leases, "took": 0.001})
	case r.Method == http.MethodDelete && len(seg) == 3:
		if a, err := netip.ParseAddr(seg[2]); err != nil || a.Zone() != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"key": "bad_request", "message": "The provided IP address is invalid", "hint": seg[2]}})
			return
		}
		if !s.dhcp.settings.Active {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
				"key": "bad_request", "message": "Failed to delete DHCP lease", "hint": "DHCP is not enabled"}})
			return
		}
		if s.dhcp.busy {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{
				"key": "service_unavailable", "message": "Failed to delete DHCP lease",
				"hint": "timed out waiting for the resolver to remove the lease"}})
			return
		}
		s.dhcp.deletes++
		if i := slices.IndexFunc(s.dhcp.leases, func(l DHCPLease) bool { return l.IP == seg[2] }); i >= 0 {
			s.dhcp.leases = slices.Delete(slices.Clone(s.dhcp.leases), i, i+1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"took": 0.001})
	default:
		writeJSON(w, http.StatusNotFound, errBody("not_found", "Not found"))
	}
}

// dhcpConfig is GET /api/config/dhcp. Called with s.mu held.
func (s *Server) dhcpConfig(detailed bool) map[string]any {
	d := s.dhcp.settings
	hosts := nonNilStrings(s.dhcp.hosts)
	leaf := func(key string, v any, typ string) any {
		if !detailed {
			return v
		}
		return map[string]any{
			"description": "", "allowed": nil, "type": typ, "value": v, "default": nil, "modified": true,
			"flags": map[string]bool{"restart_dnsmasq": true, "session_reset": false, "env_var": s.dhcp.env[key]},
		}
	}
	return map[string]any{
		"active": leaf("active", d.Active, "boolean"), "start": leaf("start", d.Start, "IPv4 address"),
		"end": leaf("end", d.End, "IPv4 address"), "router": leaf("router", d.Router, "IPv4 address"),
		"netmask": leaf("netmask", d.Netmask, "IPv4 address"), "leaseTime": leaf("leaseTime", d.LeaseTime, "string"),
		"ipv6": leaf("ipv6", d.IPv6, "boolean"), "multiDNS": leaf("multiDNS", d.MultiDNS, "boolean"),
		"rapidCommit": leaf("rapidCommit", d.RapidCommit, "boolean"), "logging": leaf("logging", d.Logging, "boolean"),
		"ignoreUnknownClients": leaf("ignoreUnknownClients", d.IgnoreUnknownClients, "boolean"),
		"hosts":                leaf("hosts", hosts, "string array"),
	}
}

// patchConfig is PATCH /api/config for the dhcp items. The caller has checked app_sudo and read-only mode. Called
// with s.mu held.
func (s *Server) patchConfig(w http.ResponseWriter, r *http.Request) {
	bad := func(message, hint string) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"key": "bad_request", "message": message, "hint": hint}})
	}
	var in struct {
		Config map[string]map[string]json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Config) == 0 {
		bad("No \"config\" JSON object in request body", "")
		return
	}
	old := s.dhcp.settings
	next := old
	sent := map[string]bool{}
	for section, items := range in.Config {
		if section != "dhcp" {
			bad("Unknown config item", "config."+section)
			return
		}
		for key, raw := range items {
			var str *string
			var flag *bool
			switch key {
			case "start":
				str = &next.Start
			case "end":
				str = &next.End
			case "router":
				str = &next.Router
			case "netmask":
				str = &next.Netmask
			case "leaseTime":
				str = &next.LeaseTime
			case "active":
				flag = &next.Active
			case "ipv6":
				flag = &next.IPv6
			case "multiDNS":
				flag = &next.MultiDNS
			case "rapidCommit":
				flag = &next.RapidCommit
			case "logging":
				flag = &next.Logging
			case "ignoreUnknownClients":
				flag = &next.IgnoreUnknownClients
			default:
				bad("Unknown config item", "dhcp."+key)
				return
			}
			if str != nil {
				if err := json.Unmarshal(raw, str); err != nil {
					bad("Invalid value", "dhcp."+key+": not a string")
					return
				}
			} else if err := json.Unmarshal(raw, flag); err != nil {
				bad("Invalid value", "dhcp."+key+": not a boolean")
				return
			}
			sent[key] = true
		}
	}
	// Items whose value didn't change are skipped by FTL.
	was, now := dhcpValues(old), dhcpValues(next)
	changed := map[string]bool{}
	for key := range sent {
		if was[key] != now[key] {
			changed[key] = true
		}
	}
	for key := range changed {
		if s.dhcp.env[key] {
			bad("Config items set via environment variables cannot be changed via the API", "dhcp."+key)
			return
		}
	}
	if problem := dhcpValidate(next, changed); problem != "" {
		bad("Config item validation failed", problem)
		return
	}
	if len(changed) > 0 {
		if problem := dnsmasqDHCPTest(next); problem != "" {
			bad("Invalid configuration", problem)
			return
		}
	}
	s.dhcp.settings = next
	if len(changed) > 0 && r.URL.Query().Get("restart") != "false" {
		s.restart()
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": map[string]any{"dhcp": s.dhcpConfig(false)}, "took": 0.001})
}

func dhcpValues(d DHCPSettings) map[string]any {
	return map[string]any{
		"active": d.Active, "start": d.Start, "end": d.End, "router": d.Router, "netmask": d.Netmask,
		"leaseTime": d.LeaseTime, "ipv6": d.IPv6, "multiDNS": d.MultiDNS, "rapidCommit": d.RapidCommit,
		"logging": d.Logging, "ignoreUnknownClients": d.IgnoreUnknownClients,
	}
}

// dhcpValidate is FTL's per-item validators, run on the items that changed: the addresses are IPv4 or empty
// (type-based checking), the netmask's one-bits are contiguous (validate_netmask), and the lease time has no line
// break (validate_str_no_newline).
func dhcpValidate(d DHCPSettings, changed map[string]bool) string {
	for _, a := range []struct{ key, v string }{{"start", d.Start}, {"end", d.End}, {"router", d.Router}, {"netmask", d.Netmask}} {
		if a.v == "" || !changed[a.key] {
			continue
		}
		if p, err := netip.ParseAddr(a.v); err != nil || !p.Is4() {
			return "dhcp." + a.key + ": not a valid IPv4 address (\"" + a.v + "\")"
		}
	}
	if d.Netmask != "" && changed["netmask"] {
		if hm := ^addr32(d.Netmask); hm&(hm+1) != 0 {
			return fmt.Sprintf("dhcp.netmask: not a valid netmask (%q), the one-bits are not contiguous", d.Netmask)
		}
	}
	if changed["leaseTime"] && strings.ContainsAny(d.LeaseTime, "\r\n") {
		return "dhcp.leaseTime: contains newline characters"
	}
	return ""
}

func addr32(s string) uint32 {
	if s == "" {
		return 0
	}
	b := netip.MustParseAddr(s).As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// dnsmasqDHCPTest is the early checks of write_dnsmasq_config, which FTL runs on the whole new config, only with
// DHCP on. It returns "" or the problem.
func dnsmasqDHCPTest(d DHCPSettings) string {
	if !d.Active {
		return ""
	}
	start, end, router := addr32(d.Start), addr32(d.End), addr32(d.Router)
	for _, a := range []struct {
		name string
		v    uint32
	}{{"start", start}, {"end", end}, {"router", router}} {
		if a.v == 0 || a.v == 0xFFFFFFFF {
			return "DHCP " + a.name + " address is not valid"
		}
	}
	mask := addr32(d.Netmask)
	if mask == 0 { // dnsmasq takes it from the interface; FTL falls back to the address's class
		switch {
		case start&0x80000000 == 0:
			mask = 0xFF000000
		case start&0xC0000000 == 0x80000000:
			mask = 0xFFFF0000
		default:
			mask = 0xFFFFFF00
		}
	}
	if hm := ^mask; hm&(hm+1) != 0 {
		return "DHCP netmask is not valid"
	}
	for _, a := range []struct {
		name string
		v    uint32
	}{{"start", start}, {"end", end}, {"router", router}} {
		switch host := a.v & ^mask; host {
		case 0:
			return "DHCP " + a.name + " address is the network address of the subnet"
		case ^mask:
			return "DHCP " + a.name + " address is the broadcast address of the subnet"
		}
	}
	if start > end {
		return "DHCP range start address is larger than the end address"
	}
	if router >= start && router <= end {
		return "DHCP router address should not be within DHCP range"
	}
	return ""
}
