// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcp

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fieldOf returns the field of a *FieldError, or "" for nil, and fails for any other error.
func fieldOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("error %v isn't a *FieldError", err)
	}
	return fe.Field
}

func TestCheckLeaseTime(t *testing.T) {
	tests := []struct {
		in, out string
		bad     bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"120", "120", false},
		{"119", "", true},
		{"2m", "2m", false},
		{"1m", "", true},
		{"45M", "45m", false},
		{"12h", "12h", false},
		{" 2d ", "2d", false},
		{"1w", "1w", false},
		{"52w", "52w", false}, // 364 days
		{"53w", "", true},
		{"365d", "365d", false},
		{"366d", "", true},
		{"31536000", "31536000", false},
		{"31536001", "", true},
		{"infinite", "", true},
		{"INFINITE", "", true},
		{"-5m", "", true},
		{"1.5h", "", true},
		{"1y", "", true},
		{"h", "", true},
		{"99999999999m", "", true},
		{"1h,ignore", "", true},
		{"1h\n", "1h", false}, // trimmed like any whitespace
	}
	for _, tt := range tests {
		got, err := CheckLeaseTime("lease_time", tt.in)
		if (err != nil) != tt.bad || got != tt.out {
			t.Errorf("%q: got %q, %v; want %q, bad=%v", tt.in, got, err, tt.out, tt.bad)
		}
		if err != nil && fieldOf(t, err) != "lease_time" {
			t.Errorf("%q: wrong field", tt.in)
		}
	}
}

func TestSubnet(t *testing.T) {
	tests := []struct {
		start, mask string
		prefix      string
		guessed, ok bool
	}{
		{"192.168.1.10", "255.255.255.0", "192.168.1.0/24", false, true},
		{"192.168.1.10", "", "192.168.1.0/24", true, true},
		{"10.1.2.3", "", "10.0.0.0/8", true, true},
		{"172.16.5.5", "", "172.16.0.0/16", true, true},
		{"10.1.2.3", "255.255.0.0", "10.1.0.0/16", false, true},
		{"10.1.2.3", "255.0.255.0", "", false, false},
		{"10.1.2.3", "0.0.0.0", "", false, false},
		{"10.1.2.3", "255.255.255.255", "", false, false},
		{"10.1.2.3", "255.255.255.252", "10.1.2.0/30", false, true},
		{"", "255.255.255.0", "", false, false},
		{"fd00::1", "", "", false, false},
	}
	for _, tt := range tests {
		p, guessed, ok := Subnet(Settings{Start: tt.start, Netmask: tt.mask})
		if ok != tt.ok || guessed != tt.guessed || (ok && p.String() != tt.prefix) {
			t.Errorf("%q %q: got %v %v %v; want %s %v %v", tt.start, tt.mask, p, guessed, ok, tt.prefix, tt.guessed, tt.ok)
		}
	}
}

func TestCheckSettings(t *testing.T) {
	good := Settings{Active: true, Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1",
		Netmask: "255.255.255.0", LeaseTime: "24h"}
	with := func(f func(*Settings)) Settings { s := good; f(&s); return s }
	tests := []struct {
		name  string
		s     Settings
		field string // "" for fine
	}{
		{"good", good, ""},
		{"empty netmask uses the class", with(func(s *Settings) { s.Netmask = "" }), ""},
		{"off and empty", Settings{}, ""},
		{"off, partly set", Settings{Start: "192.168.1.100", Router: "192.168.1.1"}, ""},
		{"off still checks formats", Settings{Start: "nonsense"}, "start"},
		{"off still checks the lease time", Settings{LeaseTime: "infinite"}, "lease_time"},
		{"off still checks the netmask", Settings{Netmask: "255.0.255.0"}, "netmask"},
		{"on, no start", with(func(s *Settings) { s.Start = "" }), "start"},
		{"on, no end", with(func(s *Settings) { s.End = " " }), "end"},
		{"on, no router", with(func(s *Settings) { s.Router = "" }), "router"},
		{"start after end", with(func(s *Settings) { s.Start, s.End = s.End, s.Start }), "start"},
		{"start equals end", with(func(s *Settings) { s.End = s.Start }), ""},
		{"router inside the range", with(func(s *Settings) { s.Router = "192.168.1.150" }), "router"},
		{"router at the range start", with(func(s *Settings) { s.Router = "192.168.1.100" }), "router"},
		{"router at the range end", with(func(s *Settings) { s.Router = "192.168.1.200" }), "router"},
		{"router just after the range", with(func(s *Settings) { s.Router = "192.168.1.201" }), ""},
		{"router elsewhere in the subnet", with(func(s *Settings) { s.Router = "192.168.1.254" }), ""},
		{"router outside the subnet", with(func(s *Settings) { s.Router = "192.168.2.1" }), "router"},
		{"end outside the subnet", with(func(s *Settings) { s.End = "192.168.2.200" }), "end"},
		{"start is the network address", with(func(s *Settings) { s.Start = "192.168.1.0" }), "start"},
		{"end is the broadcast address", with(func(s *Settings) { s.End = "192.168.1.255" }), "end"},
		{"x.x.x.255 is fine in a /16", with(func(s *Settings) {
			s.Netmask, s.Start, s.End, s.Router = "255.255.0.0", "10.1.0.10", "10.1.1.255", "10.1.0.1"
		}), ""},
		{"x.x.x.0 is fine in a /16", with(func(s *Settings) {
			s.Netmask, s.Start, s.End, s.Router = "255.255.0.0", "10.1.1.0", "10.1.2.20", "10.1.0.1"
		}), ""},
		{"netmask not contiguous", with(func(s *Settings) { s.Netmask = "255.0.255.0" }), "netmask"},
		{"netmask is an address", with(func(s *Settings) { s.Netmask = "192.168.1.1" }), "netmask"},
		{"ipv6 address", with(func(s *Settings) { s.Router = "fd00::1" }), "router"},
		{"mapped ipv6 address", with(func(s *Settings) { s.Router = "::ffff:192.168.1.1" }), "router"},
		{"loopback", with(func(s *Settings) { s.Router = "127.0.0.1" }), "router"},
		{"bad lease time", with(func(s *Settings) { s.LeaseTime = "1y" }), "lease_time"},
		{"empty lease time", with(func(s *Settings) { s.LeaseTime = "" }), ""},
		{"classful guess catches a router outside it", with(func(s *Settings) {
			s.Netmask, s.Router = "", "192.168.2.1"
		}), "router"},
	}
	for _, tt := range tests {
		if got := fieldOf(t, CheckSettings(tt.s)); got != tt.field {
			t.Errorf("%s: field %q, want %q (%v)", tt.name, got, tt.field, CheckSettings(tt.s))
		}
	}
}

func TestParseStatic(t *testing.T) {
	tests := []struct {
		value    string
		mac, ip  string
		hostname string
		marks    []string
		key      string
	}{
		{"aa:bb:cc:dd:ee:ff,10.0.0.20", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", nil, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"AA:BB:CC:DD:EE:FF,10.0.0.20,Printer", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "printer", nil, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa-bb-cc-dd-ee-ff, 10.0.0.20 ,printer", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "printer", nil, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"printer,10.0.0.20,aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "printer", nil, "aa:bb:cc:dd:ee:ff|10.0.0.20"}, // dnsmasq takes fields in any order
		{"00:20:e0:3b:13:af,192.168.0.123,laptop,24h", "00:20:e0:3b:13:af", "192.168.0.123", "laptop", []string{MarkExtraFields}, "00:20:e0:3b:13:af|192.168.0.123"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20,infinite", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20,ignore", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,set:lab,10.0.0.20", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,tag:lab,10.0.0.20", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,id:*,10.0.0.20", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20,a,b", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "a", []string{MarkExtraFields}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,bb:bb:cc:dd:ee:ff,10.0.0.20", "aa:bb:cc:dd:ee:ff", "10.0.0.20", "", []string{MarkMultipleMACs}, "aa:bb:cc:dd:ee:ff|10.0.0.20"},
		{"id:abc,10.0.0.20", "", "10.0.0.20", "", []string{MarkNoMAC, MarkExtraFields}, "|10.0.0.20"},
		{"10.0.0.20,printer", "", "10.0.0.20", "printer", []string{MarkNoMAC}, "|10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,[fd00::20]", "aa:bb:cc:dd:ee:ff", "", "", []string{MarkIPv6}, "aa:bb:cc:dd:ee:ff|"},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "", "", nil, "aa:bb:cc:dd:ee:ff|"},
		{"aa:bb:cc:*:*:*,10.0.0.20", "", "", "", []string{MarkUnparsed}, "aa:bb:cc:*:*:*,10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20,print.er", "", "", "", []string{MarkUnparsed}, "aa:bb:cc:dd:ee:ff,10.0.0.20,print.er"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20,", "", "", "", []string{MarkUnparsed}, "aa:bb:cc:dd:ee:ff,10.0.0.20,"},
		{",10.0.0.20", "", "", "", []string{MarkUnparsed}, ",10.0.0.20"},
		{"aa:bb:cc:dd:ee:ff,10.0.0.20\n--evil", "", "", "", []string{MarkUnparsed}, "aa:bb:cc:dd:ee:ff,10.0.0.20\n--evil"},
		{"", "", "", "", []string{MarkUnparsed}, ""},
	}
	for _, tt := range tests {
		s := ParseStatic(tt.value)
		if s.Value != tt.value || s.MAC != tt.mac || s.IP != tt.ip || s.Hostname != tt.hostname ||
			!slices.Equal(s.Marks, tt.marks) || s.Key != tt.key {
			t.Errorf("%q: got %+v; want mac %q ip %q name %q marks %q key %q", tt.value, s,
				tt.mac, tt.ip, tt.hostname, tt.marks, tt.key)
		}
		if s.Writable() != (len(tt.marks) == 0) {
			t.Errorf("%q: Writable %v", tt.value, s.Writable())
		}
	}
}

func TestNewStatic(t *testing.T) {
	lan := &Settings{Active: true, Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1", Netmask: "255.255.255.0"}
	tests := []struct {
		name          string
		mac, ip, host string
		settings      *Settings
		value, field  string
	}{
		{"plain", "AA:BB:CC:DD:EE:FF", "192.168.1.50", "", lan, "aa:bb:cc:dd:ee:ff,192.168.1.50", ""},
		{"with a name", "aa-bb-cc-dd-ee-ff", "192.168.1.50", " Printer ", lan, "aa:bb:cc:dd:ee:ff,192.168.1.50,printer", ""},
		{"no settings, no subnet check", "aa:bb:cc:dd:ee:ff", "10.9.9.9", "nas", nil, "aa:bb:cc:dd:ee:ff,10.9.9.9,nas", ""},
		{"settings without a start", "aa:bb:cc:dd:ee:ff", "10.9.9.9", "", &Settings{}, "aa:bb:cc:dd:ee:ff,10.9.9.9", ""},
		{"outside the subnet", "aa:bb:cc:dd:ee:ff", "192.168.2.50", "", lan, "", "ip"},
		{"outside the range but in the subnet", "aa:bb:cc:dd:ee:ff", "192.168.1.250", "", lan, "aa:bb:cc:dd:ee:ff,192.168.1.250", ""},
		{"network address", "aa:bb:cc:dd:ee:ff", "192.168.1.0", "", lan, "", "ip"},
		{"broadcast address", "aa:bb:cc:dd:ee:ff", "192.168.1.255", "", lan, "", "ip"},
		{"ipv6", "aa:bb:cc:dd:ee:ff", "fd00::5", "", lan, "", "ip"},
		{"loopback", "aa:bb:cc:dd:ee:ff", "127.0.0.1", "", nil, "", "ip"},
		{"short mac", "aa:bb:cc:dd:ee", "192.168.1.50", "", lan, "", "mac"},
		{"eight octet mac", "00:11:22:33:44:55:66:77", "192.168.1.50", "", lan, "", "mac"},
		{"group mac", "01:00:5e:00:00:01", "192.168.1.50", "", lan, "", "mac"},
		{"zero mac", "00:00:00:00:00:00", "192.168.1.50", "", lan, "", "mac"},
		{"mac with a comma", "aa:bb:cc:dd:ee:ff,ignore", "192.168.1.50", "", lan, "", "mac"},
		{"ip with a comma", "aa:bb:cc:dd:ee:ff", "192.168.1.50,ignore", "", lan, "", "ip"},
		{"name with a comma", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "a,ignore", lan, "", "hostname"},
		{"name with a newline", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "a\nb", lan, "", "hostname"},
		{"dotted name", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "nas.lab", lan, "", "hostname"},
		{"name that reads as a lease time", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "24h", lan, "", "hostname"},
		{"all-digit name", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "12345", lan, "", "hostname"},
		{"name that reads as ignore", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "ignore", lan, "", "hostname"},
		{"name that reads as infinite", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "Infinite", lan, "", "hostname"},
		{"name with a tag prefix", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "set:x", lan, "", "hostname"},
		{"underscore name", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "my_host", lan, "", "hostname"},
		{"hyphen name", "aa:bb:cc:dd:ee:ff", "192.168.1.50", "my-host2", lan, "aa:bb:cc:dd:ee:ff,192.168.1.50,my-host2", ""},
	}
	for _, tt := range tests {
		s, err := NewStatic(tt.mac, tt.ip, tt.host, tt.settings)
		if got := fieldOf(t, err); got != tt.field {
			t.Errorf("%s: field %q, want %q (%v)", tt.name, got, tt.field, err)
			continue
		}
		if err == nil {
			if s.Value != tt.value {
				t.Errorf("%s: value %q, want %q", tt.name, s.Value, tt.value)
			}
			// What the app builds reads back as a plain lease with the same key.
			back := ParseStatic(s.Value)
			if !back.Writable() || back.Key != s.Key || back.MAC != s.MAC || back.IP != s.IP || back.Hostname != s.Hostname {
				t.Errorf("%s: %q reads back as %+v", tt.name, s.Value, back)
			}
			if strings.ContainsAny(s.Value, "\r\n\t ") {
				t.Errorf("%s: %q holds whitespace", tt.name, s.Value)
			}
		}
	}
}

func TestConflict(t *testing.T) {
	existing := []Static{
		ParseStatic("aa:bb:cc:dd:ee:01,10.0.0.21,one"),
		ParseStatic("aa:bb:cc:dd:ee:02,10.0.0.22,two,24h"), // marked, but still counts
		ParseStatic("garbage,here"),                        // unparsed: ignored
	}
	tests := []struct {
		mac, ip string
		field   string
		value   string
	}{
		{"aa:bb:cc:dd:ee:03", "10.0.0.23", "", ""},
		{"aa:bb:cc:dd:ee:01", "10.0.0.99", "mac", existing[0].Value},
		{"aa:bb:cc:dd:ee:99", "10.0.0.21", "ip", existing[0].Value},
		{"aa:bb:cc:dd:ee:02", "10.0.0.22", "mac", existing[1].Value},
		{"aa:bb:cc:dd:ee:99", "10.0.0.22", "ip", existing[1].Value},
	}
	for _, tt := range tests {
		field, other, found := Conflict(existing, tt.mac, tt.ip)
		if field != tt.field || found != (tt.field != "") || other.Value != tt.value {
			t.Errorf("%s %s: got %q %q %v; want %q %q", tt.mac, tt.ip, field, other.Value, found, tt.field, tt.value)
		}
	}
	// A change leaves the lease being replaced out of the list, so it doesn't clash with itself.
	if _, _, found := Conflict(existing[1:], "aa:bb:cc:dd:ee:01", "10.0.0.21"); found {
		t.Error("a lease clashed with one that was left out")
	}
}

func TestNormalize(t *testing.T) {
	got := Normalize(Settings{Start: " 192.168.001.10", End: "192.168.1.20 ", Router: "192.168.1.1", Netmask: "255.255.255.0", LeaseTime: " 24H "})
	// 192.168.001.10 doesn't parse (leading zeros), so it is left for CheckSettings to refuse.
	if got.Start != "192.168.001.10" || got.End != "192.168.1.20" || got.LeaseTime != "24h" {
		t.Fatalf("Normalize = %+v", got)
	}
	if err := CheckSettings(Settings{Active: true, Start: got.Start, End: got.End, Router: got.Router, Netmask: got.Netmask}); err == nil {
		t.Fatal("a start with leading zeros was accepted")
	}
	if got := Normalize(Settings{}); got != (Settings{}) {
		t.Fatalf("empty settings changed: %+v", got)
	}
}
