// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

// lan is a working DHCP setup: a /24 with the router below the range.
var lan = piholetest.DHCPSettings{
	Active: true, Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1",
	Netmask: "255.255.255.0", LeaseTime: "24h",
}

func TestGetDHCP(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	c := newClient(t, ph.URL)

	got, err := c.GetDHCP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Active || got.Start != "" || got.Hosts == nil || len(got.Hosts) != 0 || got.AppSudo || got.ReadOnly || len(got.Locked) != 0 {
		t.Errorf("empty config read as %+v", got)
	}

	settings := lan
	settings.IPv6, settings.MultiDNS, settings.RapidCommit, settings.IgnoreUnknownClients = true, true, true, true
	ph.SetDHCP(settings)
	ph.SetStaticLeases([]string{"aa:bb:cc:dd:ee:ff,192.168.1.20,printer", "00:20:e0:3b:13:af,192.168.1.21,laptop,24h"})
	ph.SetAppSudo(true)
	ph.SetConfigReadOnly(true)
	ph.LockDHCP("start", "hosts")
	got, err = c.GetDHCP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active || got.Start != "192.168.1.100" || got.End != "192.168.1.200" || got.Router != "192.168.1.1" ||
		got.Netmask != "255.255.255.0" || got.LeaseTime != "24h" || !got.IPv6 || !got.RapidCommit || !got.MultiDNS || !got.IgnoreUnknownClients {
		t.Errorf("settings read as %+v", got)
	}
	if !slices.Equal(got.Hosts, ph.StaticLeases()) {
		t.Errorf("hosts read as %q, want the strings exactly as Pi-hole holds them", got.Hosts)
	}
	if !got.AppSudo || !got.ReadOnly || !got.Locked["start"] || !got.Locked["hosts"] || got.Locked["end"] || len(got.Locked) != 2 {
		t.Errorf("flags %+v", got)
	}
	reqs := ph.Requests()
	for _, want := range []string{"GET /api/config/dhcp", "GET /api/config/webserver/api/app_sudo", "GET /api/config/misc/readOnly"} {
		if !slices.Contains(reqs, want) {
			t.Errorf("requests %q don't include %q", reqs, want)
		}
	}
	if ph.Restarts() != 0 {
		t.Error("a read restarted FTL")
	}
}

func TestLeases(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	c := newClient(t, ph.URL)

	// Leases are listed whether or not DHCP is on, and "*" means none.
	leases, err := c.GetLeases(ctx)
	if err != nil || leases == nil || len(leases) != 0 {
		t.Fatalf("no leases read as %v, %v; want an empty list", leases, err)
	}
	ph.SetLeases([]piholetest.DHCPLease{
		{Expires: 1800000000, HWAddr: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.101", Name: "phone", ClientID: "01:aa:bb:cc:dd:ee:ff"},
		{Expires: 0, HWAddr: "aa:bb:cc:dd:ee:01", IP: "192.168.1.102", Name: "*", ClientID: "*"},
		{Expires: 1800000000, HWAddr: "1234", IP: "fd00::5", Name: "v6", ClientID: "00:01"},
	})
	leases, err = c.GetLeases(ctx)
	if err != nil || len(leases) != 3 {
		t.Fatalf("read %v, %v", leases, err)
	}
	if leases[0].Name != "phone" || leases[0].ClientID != "01:aa:bb:cc:dd:ee:ff" || leases[1].Name != "" || leases[1].ClientID != "" || leases[1].Expires != 0 {
		t.Errorf("leases read as %+v", leases)
	}
	if leases[0].IsIPv6() || !leases[2].IsIPv6() {
		t.Error("IsIPv6 is wrong")
	}

	tests := []struct {
		name  string
		setup func()
		ip    string
		sent  string
		code  string
		is    error
		not   bool // a 404 StatusError
		left  int
	}{
		{name: "dhcp off", ip: "192.168.1.101", sent: "DELETE /api/dhcp/leases/192.168.1.101", code: piholeapi.CodeDHCPOff, is: piholeapi.ErrDHCPOff, left: 3},
		{name: "deleted", setup: func() { ph.SetDHCP(lan) }, ip: "192.168.1.101", sent: "DELETE /api/dhcp/leases/192.168.1.101", left: 2},
		{name: "not found", ip: "192.168.1.101", sent: "DELETE /api/dhcp/leases/192.168.1.101", not: true, code: piholeapi.CodeStatusError, left: 2},
		{name: "ipv6", ip: "fd00::5", sent: "DELETE /api/dhcp/leases/fd00::5", left: 1},
		{name: "busy", setup: func() { ph.SetLeaseBusy(true) }, ip: "192.168.1.102", sent: "DELETE /api/dhcp/leases/192.168.1.102", code: piholeapi.CodeBusy, is: piholeapi.ErrBusy, left: 1},
		{name: "not an address", ip: "192.168.1.101; rm", code: "", is: piholeapi.ErrInvalidArgument, left: 1},
		{name: "a path", ip: "../config", code: "", is: piholeapi.ErrInvalidArgument, left: 1},
		{name: "not canonical", ip: "fd00:0:0::5", code: "", is: piholeapi.ErrInvalidArgument, left: 1},
		{name: "with a zone", ip: "fe80::1%eth0", code: "", is: piholeapi.ErrInvalidArgument, left: 1},
		{name: "empty", ip: "", code: "", is: piholeapi.ErrInvalidArgument, left: 1},
	}
	for _, tt := range tests {
		if tt.setup != nil {
			tt.setup()
		}
		before := len(ph.Requests())
		err := c.DeleteLease(ctx, tt.ip)
		var se *piholeapi.StatusError
		switch {
		case tt.is != nil:
			if !errors.Is(err, tt.is) {
				t.Errorf("%s: %v, want %v", tt.name, err, tt.is)
			}
		case tt.not:
			if !errors.As(err, &se) || se.Code != http.StatusNotFound {
				t.Errorf("%s: %v, want a 404", tt.name, err)
			}
		case err != nil:
			t.Errorf("%s: %v", tt.name, err)
		}
		if got := piholeapi.Kind(err); got != tt.code {
			t.Errorf("%s: Kind %q, want %q", tt.name, got, tt.code)
		}
		sent := ph.Requests()[before:]
		if tt.sent == "" && len(sent) != 0 || tt.sent != "" && !slices.Contains(sent, tt.sent) {
			t.Errorf("%s: sent %q, want %q", tt.name, sent, tt.sent)
		}
		if got := len(ph.Leases()); got != tt.left {
			t.Errorf("%s: %d leases left, want %d", tt.name, got, tt.left)
		}
	}
	if ph.Restarts() != 0 {
		t.Error("deleting a lease restarted FTL")
	}
}

// TestPatchDHCP covers the settings change against the fake, which answers as FTL does: a write needs app_sudo, an
// item set by an environment variable is refused, the new settings are checked as a whole and a refusal applies
// nothing, and a change restarts FTL unless told not to.
func TestPatchDHCP(t *testing.T) {
	ctx := context.Background()
	off := piholetest.DHCPSettings{Logging: true} // logging is never touched by the app
	tests := []struct {
		name     string
		setup    func(ph *piholetest.Server)
		patch    piholeapi.DHCPPatch
		restart  bool
		code     string
		is       error
		rejected string // part of Pi-hole's reason
		want     piholetest.DHCPSettings
		restarts int
	}{
		{
			name: "turn on", patch: piholeapi.DHCPPatch{Active: ptr(true), Start: ptr("192.168.1.100"), End: ptr("192.168.1.200"),
				Router: ptr("192.168.1.1"), Netmask: ptr("255.255.255.0"), LeaseTime: ptr("12h")},
			restart: true, restarts: 1,
			want: piholetest.DHCPSettings{Active: true, Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1",
				Netmask: "255.255.255.0", LeaseTime: "12h", Logging: true},
		},
		{
			name: "without a restart", patch: piholeapi.DHCPPatch{LeaseTime: ptr("1h")}, restart: false, restarts: 0,
			want: piholetest.DHCPSettings{LeaseTime: "1h", Logging: true},
		},
		{
			name: "only what is sent changes", setup: func(ph *piholetest.Server) { ph.SetDHCP(lan) },
			patch: piholeapi.DHCPPatch{IPv6: ptr(true), IgnoreUnknownClients: ptr(true)}, restart: true, restarts: 1,
			want: func() piholetest.DHCPSettings { s := lan; s.IPv6, s.IgnoreUnknownClients = true, true; return s }(),
		},
		{
			name: "an empty value clears it", setup: func(ph *piholetest.Server) { ph.SetDHCP(lan) },
			patch: piholeapi.DHCPPatch{Active: ptr(false), Netmask: ptr("")}, restart: true, restarts: 1,
			want: func() piholetest.DHCPSettings { s := lan; s.Active, s.Netmask = false, ""; return s }(),
		},
		{
			name: "app_sudo off", setup: func(ph *piholetest.Server) { ph.SetAppSudo(false) },
			patch: piholeapi.DHCPPatch{LeaseTime: ptr("1h")}, restart: true, code: piholeapi.CodeAppSudoOff, is: piholeapi.ErrAppSudoOff, want: off,
		},
		{
			name: "read-only config", setup: func(ph *piholetest.Server) { ph.SetConfigReadOnly(true) },
			patch: piholeapi.DHCPPatch{LeaseTime: ptr("1h")}, restart: true, code: piholeapi.CodeConfigLocked, is: piholeapi.ErrConfigLocked, want: off,
		},
		{
			name: "set by an environment variable", setup: func(ph *piholetest.Server) { ph.LockDHCP("leaseTime") },
			patch: piholeapi.DHCPPatch{LeaseTime: ptr("1h")}, restart: true, code: piholeapi.CodeConfigLocked, is: piholeapi.ErrConfigLocked, want: off,
		},
		{
			name: "router inside the range", patch: piholeapi.DHCPPatch{Active: ptr(true), Start: ptr("192.168.1.100"), End: ptr("192.168.1.200"),
				Router: ptr("192.168.1.150"), Netmask: ptr("255.255.255.0")},
			restart: true, code: piholeapi.CodeRejected, rejected: "router address should not be within DHCP range", want: off,
		},
		{
			name: "start after end", patch: piholeapi.DHCPPatch{Active: ptr(true), Start: ptr("192.168.1.200"), End: ptr("192.168.1.100"),
				Router: ptr("192.168.1.1")},
			restart: true, code: piholeapi.CodeRejected, rejected: "start address is larger than the end address", want: off,
		},
		{
			name:    "on with nothing set",
			patch:   piholeapi.DHCPPatch{Active: ptr(true)},
			restart: true, code: piholeapi.CodeRejected, rejected: "start address is not valid", want: off,
		},
		{
			name: "broadcast address", patch: piholeapi.DHCPPatch{Active: ptr(true), Start: ptr("192.168.1.100"), End: ptr("192.168.1.255"),
				Router: ptr("192.168.1.1"), Netmask: ptr("255.255.255.0")},
			restart: true, code: piholeapi.CodeRejected, rejected: "broadcast address", want: off,
		},
		{
			name: "netmask not contiguous", patch: piholeapi.DHCPPatch{Netmask: ptr("255.0.255.0")},
			restart: true, code: piholeapi.CodeRejected, rejected: "one-bits are not contiguous", want: off,
		},
		{
			name: "not an address", patch: piholeapi.DHCPPatch{Start: ptr("lan")},
			restart: true, code: piholeapi.CodeRejected, rejected: "not a valid IPv4 address", want: off,
		},
		{
			name: "an unchanged value isn't a change", setup: func(ph *piholetest.Server) { ph.SetDHCP(lan) },
			patch: piholeapi.DHCPPatch{LeaseTime: ptr("24h"), Active: ptr(true)}, restart: true, restarts: 0, want: lan,
		},
		{
			name: "unchanged but set by an environment variable", setup: func(ph *piholetest.Server) { ph.SetDHCP(lan); ph.LockDHCP("leaseTime") },
			patch: piholeapi.DHCPPatch{LeaseTime: ptr("24h"), IPv6: ptr(true)}, restart: true, restarts: 1,
			want: func() piholetest.DHCPSettings { s := lan; s.IPv6 = true; return s }(),
		},
		{name: "nothing to change", patch: piholeapi.DHCPPatch{}, restart: true, is: piholeapi.ErrInvalidArgument, want: off},
		{name: "a line break", patch: piholeapi.DHCPPatch{LeaseTime: ptr("1h\ndhcp-option=evil")}, restart: true, is: piholeapi.ErrInvalidArgument, want: off},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			ph.SetAppSudo(true)
			ph.SetDHCP(off)
			if tt.setup != nil {
				tt.setup(ph)
			}
			c := newClient(t, ph.URL)
			err := c.PatchDHCP(ctx, tt.patch, tt.restart)
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("error %v, want %v", err, tt.is)
			}
			if tt.is == nil && tt.rejected == "" && err != nil {
				t.Errorf("error %v", err)
			}
			if tt.rejected != "" {
				var re *piholeapi.RejectedError
				if !errors.As(err, &re) || !containsFold(re.Message, tt.rejected) {
					t.Errorf("error %v, want a refusal mentioning %q", err, tt.rejected)
				}
			}
			if got := piholeapi.Kind(err); got != tt.code {
				t.Errorf("Kind %q, want %q", got, tt.code)
			}
			if got := ph.DHCP(); got != tt.want {
				t.Errorf("settings now %+v, want %+v", got, tt.want)
			}
			if got := ph.Restarts(); got != tt.restarts {
				t.Errorf("%d restarts, want %d", got, tt.restarts)
			}
		})
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// TestStaticLeaseWrites covers adding and deleting static leases against the fake: the value is the rest of the path,
// matched exactly; a duplicate add is refused; a missing delete is a 404; FTL checks only for line breaks; writes need
// app_sudo; every write restarts FTL unless told not to.
func TestStaticLeaseWrites(t *testing.T) {
	ctx := context.Background()
	seed := []string{"aa:bb:cc:dd:ee:ff,192.168.1.20,printer", "00:20:e0:3b:13:af,192.168.1.21,laptop,24h"}
	tests := []struct {
		name     string
		setup    func(ph *piholetest.Server)
		call     func(c *piholeapi.Client) error
		sent     string
		code     string
		is       error
		hosts    []string
		restarts int
	}{
		{
			name: "add", call: func(c *piholeapi.Client) error {
				return c.AddStaticLease(ctx, "aa:bb:cc:dd:ee:01,192.168.1.22,tv", true)
			},
			sent:  "PUT /api/config/dhcp/hosts/aa:bb:cc:dd:ee:01%2C192.168.1.22%2Ctv",
			hosts: append(slices.Clone(seed), "aa:bb:cc:dd:ee:01,192.168.1.22,tv"), restarts: 1,
		},
		{
			name: "add without a restart", call: func(c *piholeapi.Client) error { return c.AddStaticLease(ctx, "aa:bb:cc:dd:ee:01,192.168.1.22", false) },
			sent:  "PUT /api/config/dhcp/hosts/aa:bb:cc:dd:ee:01%2C192.168.1.22",
			hosts: append(slices.Clone(seed), "aa:bb:cc:dd:ee:01,192.168.1.22"),
		},
		{
			name: "duplicate", call: func(c *piholeapi.Client) error { return c.AddStaticLease(ctx, seed[0], true) },
			code: piholeapi.CodeAlreadyPresent, is: piholeapi.ErrAlreadyPresent, hosts: seed,
		},
		{
			name: "delete", call: func(c *piholeapi.Client) error { return c.DeleteStaticLease(ctx, seed[1], true) },
			sent: "DELETE /api/config/dhcp/hosts/00:20:e0:3b:13:af%2C192.168.1.21%2Claptop%2C24h", hosts: seed[:1], restarts: 1,
		},
		{
			name: "delete without a restart", call: func(c *piholeapi.Client) error { return c.DeleteStaticLease(ctx, seed[0], false) },
			sent: "DELETE /api/config/dhcp/hosts/aa:bb:cc:dd:ee:ff%2C192.168.1.20%2Cprinter", hosts: seed[1:],
		},
		{
			name: "delete one that isn't there", call: func(c *piholeapi.Client) error {
				return c.DeleteStaticLease(ctx, "aa:bb:cc:dd:ee:99,192.168.1.99", true)
			},
			code: piholeapi.CodeStatusError, hosts: seed,
		},
		{
			name: "a line break", call: func(c *piholeapi.Client) error {
				return c.AddStaticLease(ctx, "aa:bb:cc:dd:ee:01,192.168.1.22\ndhcp-option=evil", true)
			},
			is: piholeapi.ErrInvalidArgument, hosts: seed,
		},
		{
			name: "empty", call: func(c *piholeapi.Client) error { return c.AddStaticLease(ctx, "", true) },
			is: piholeapi.ErrInvalidArgument, hosts: seed,
		},
		{
			name: "app_sudo off", setup: func(ph *piholetest.Server) { ph.SetAppSudo(false) },
			call: func(c *piholeapi.Client) error { return c.AddStaticLease(ctx, "aa:bb:cc:dd:ee:01,192.168.1.22", true) },
			code: piholeapi.CodeAppSudoOff, is: piholeapi.ErrAppSudoOff, hosts: seed,
		},
		{
			name: "set by an environment variable", setup: func(ph *piholetest.Server) { ph.LockDHCP("hosts") },
			call: func(c *piholeapi.Client) error { return c.DeleteStaticLease(ctx, seed[0], true) },
			code: piholeapi.CodeConfigLocked, is: piholeapi.ErrConfigLocked, hosts: seed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			ph.SetAppSudo(true)
			ph.SetStaticLeases(seed)
			if tt.setup != nil {
				tt.setup(ph)
			}
			err := tt.call(newClient(t, ph.URL))
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("error %v, want %v", err, tt.is)
			}
			if tt.is == nil && tt.code == "" && err != nil {
				t.Errorf("error %v", err)
			}
			if got := piholeapi.Kind(err); got != tt.code {
				t.Errorf("Kind %q, want %q", got, tt.code)
			}
			if tt.sent != "" && !slices.Contains(ph.Requests(), tt.sent) {
				t.Errorf("requests %q don't include %q", ph.Requests(), tt.sent)
			}
			if got := ph.StaticLeases(); !slices.Equal(got, tt.hosts) {
				t.Errorf("hosts now %q, want %q", got, tt.hosts)
			}
			if got := ph.Restarts(); got != tt.restarts {
				t.Errorf("%d restarts, want %d", got, tt.restarts)
			}
		})
	}
}
