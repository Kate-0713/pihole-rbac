// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package localdns

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func ptr(n int) *int { return &n }

func TestParseHost(t *testing.T) {
	tests := []struct {
		value     string
		ip        string
		hostnames []string
		comment   string
		marks     []string
		key       string
	}{
		{"10.0.0.5 nas.lab", "10.0.0.5", []string{"nas.lab"}, "", nil, "10.0.0.5 nas.lab"},
		{"10.0.0.5  NAS.lab", "10.0.0.5", []string{"NAS.lab"}, "", nil, "10.0.0.5 nas.lab"},
		{"  10.0.0.5\tnas", "10.0.0.5", []string{"nas"}, "", nil, "10.0.0.5 nas"},
		{"fd00:0:0::5 nas.lab", "fd00::5", []string{"nas.lab"}, "", nil, "fd00::5 nas.lab"},
		{"10.0.0.5 nas.lab nas", "10.0.0.5", []string{"nas.lab", "nas"}, "", []string{MarkMultipleNames}, "10.0.0.5 nas.lab nas"},
		{"10.0.0.5 nas.lab # the NAS", "10.0.0.5", []string{"nas.lab"}, "the NAS", []string{MarkComment}, "10.0.0.5 nas.lab"},
		{"10.0.0.5 a b #x", "10.0.0.5", []string{"a", "b"}, "x", []string{MarkMultipleNames, MarkComment}, "10.0.0.5 a b"},
		{"10.0.0.5 my_host", "10.0.0.5", []string{"my_host"}, "", nil, "10.0.0.5 my_host"},
		{"10.0.0.5", "", nil, "", []string{MarkUnparsed}, "10.0.0.5"},
		{"10.0.0.5 # only a comment", "", nil, "", []string{MarkUnparsed}, "10.0.0.5 # only a comment"},
		{"nas.lab 10.0.0.5", "", nil, "", []string{MarkUnparsed}, "nas.lab 10.0.0.5"},
		{"fe80::1%eth0 nas", "", nil, "", []string{MarkUnparsed}, "fe80::1%eth0 nas"},
		{"10.0.0.5 nas\nevil", "", nil, "", []string{MarkUnparsed}, "10.0.0.5 nas\nevil"},
		{"", "", nil, "", []string{MarkUnparsed}, ""},
	}
	for _, tt := range tests {
		h := ParseHost(tt.value)
		if h.Value != tt.value {
			t.Errorf("%q: value %q", tt.value, h.Value)
		}
		ip := ""
		if h.IP.IsValid() {
			ip = h.IP.String()
		}
		if ip != tt.ip || !slices.Equal(h.Hostnames, tt.hostnames) || h.Comment != tt.comment ||
			!slices.Equal(h.Marks, tt.marks) || h.Key != tt.key {
			t.Errorf("%q: got ip %q names %q comment %q marks %q key %q; want %q %q %q %q %q", tt.value,
				ip, h.Hostnames, h.Comment, h.Marks, h.Key, tt.ip, tt.hostnames, tt.comment, tt.marks, tt.key)
		}
	}
}

func TestParseCNAME(t *testing.T) {
	tests := []struct {
		value   string
		aliases []string
		target  string
		ttl     *int
		comment string
		marks   []string
		key     string
	}{
		{"alias.lab,nas.lab", []string{"alias.lab"}, "nas.lab", nil, "", nil, "alias.lab,nas.lab"},
		{"alias.lab,nas.lab,300", []string{"alias.lab"}, "nas.lab", ptr(300), "", nil, "alias.lab,nas.lab,300"},
		{"Alias.lab , NAS.lab , 300", []string{"Alias.lab"}, "NAS.lab", ptr(300), "", nil, "alias.lab,nas.lab,300"},
		{"a.lab,b.lab,nas.lab", []string{"a.lab", "b.lab"}, "nas.lab", nil, "", []string{MarkMultipleNames}, "a.lab,b.lab,nas.lab"},
		{"a.lab,b.lab,nas.lab,60", []string{"a.lab", "b.lab"}, "nas.lab", ptr(60), "", []string{MarkMultipleNames}, "a.lab,b.lab,nas.lab,60"},
		{"alias.lab,nas.lab #why", []string{"alias.lab"}, "nas.lab", nil, "why", []string{MarkComment}, "alias.lab,nas.lab"},
		{"alias.lab,nas#lab", []string{"alias.lab"}, "nas#lab", nil, "", nil, "alias.lab,nas#lab"},
		// A number with no alias in front of it is a target, as dnsmasq reads it: two parts are always alias, target.
		{"alias.lab,300", []string{"alias.lab"}, "300", nil, "", nil, "alias.lab,300"},
		{"alias.lab", nil, "", nil, "", []string{MarkUnparsed}, "alias.lab"},
		{"alias.lab,,nas.lab", nil, "", nil, "", []string{MarkUnparsed}, "alias.lab,,nas.lab"},
		{"alias lab,nas.lab", nil, "", nil, "", []string{MarkUnparsed}, "alias lab,nas.lab"},
		{"#alias.lab,nas.lab", nil, "", nil, "", []string{MarkUnparsed}, "#alias.lab,nas.lab"},
		{"alias.lab,nas.lab\n", nil, "", nil, "", []string{MarkUnparsed}, "alias.lab,nas.lab\n"},
		{"a,b,99999999999999999999", nil, "", nil, "", []string{MarkUnparsed}, "a,b,99999999999999999999"},
	}
	for _, tt := range tests {
		c := ParseCNAME(tt.value)
		if !slices.Equal(c.Aliases, tt.aliases) || c.Target != tt.target || !sameTTL(c.TTL, tt.ttl) ||
			c.Comment != tt.comment || !slices.Equal(c.Marks, tt.marks) || c.Key != tt.key || c.Value != tt.value {
			t.Errorf("%q: got aliases %q target %q ttl %v comment %q marks %q key %q", tt.value,
				c.Aliases, c.Target, c.TTL, c.Comment, c.Marks, c.Key)
		}
	}
}

func sameTTL(a, b *int) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func TestCheckName(t *testing.T) {
	long := strings.Repeat("a", 63)
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"nas.lab", "nas.lab", true},
		{"NAS.Lab", "nas.lab", true},
		{"  nas  ", "nas", true},
		{"nas", "nas", true},
		{"a-b.c-d.e1", "a-b.c-d.e1", true},
		{"xn--bcher-kva.lab", "xn--bcher-kva.lab", true},
		{long + ".lab", long + ".lab", true},
		{strings.Repeat("a.", 126) + "a", strings.Repeat("a.", 126) + "a", true}, // 253
		{"", "", false},
		{"   ", "", false},
		{strings.Repeat("a.", 126) + "ab", "", false}, // 254
		{long + "a.lab", "", false},
		{"nas.lab.", "", false},
		{".nas.lab", "", false},
		{"nas..lab", "", false},
		{"-nas.lab", "", false},
		{"nas-.lab", "", false},
		{"nas.-lab", "", false},
		{"my_host.lab", "", false},
		{"nas lab", "", false},
		{"nas,lab", "", false},
		{"nas#lab", "", false},
		{"nas\tlab", "", false},
		{"nas\nlab", "", false},
		{"nas/lab", "", false},
		{"bücher.lab", "", false},
		{"*.lab", "", false},
	}
	for _, tt := range tests {
		got, err := CheckName("hostname", tt.in)
		if tt.ok != (err == nil) || got != tt.want {
			t.Errorf("CheckName(%q) = %q, %v; want %q, ok %v", tt.in, got, err, tt.want, tt.ok)
		}
		var fe *FieldError
		if err != nil && (!errors.As(err, &fe) || fe.Field != "hostname" || fe.Message == "") {
			t.Errorf("CheckName(%q): error %#v isn't a FieldError for hostname", tt.in, err)
		}
		if err != nil && strings.Contains(err.Error(), tt.in) && strings.TrimSpace(tt.in) != "" {
			t.Errorf("CheckName(%q): the message repeats the name: %v", tt.in, err)
		}
	}
}

func TestNewHost(t *testing.T) {
	tests := []struct {
		ip, hostname string
		value, field string
	}{
		{"10.0.0.5", "nas.lab", "10.0.0.5 nas.lab", ""},
		{" 10.0.0.5 ", "NAS.lab", "10.0.0.5 nas.lab", ""},
		{"FD00:0::5", "nas", "fd00::5 nas", ""},
		{"::ffff:10.0.0.5", "nas", "::ffff:10.0.0.5 nas", ""},
		{"0.0.0.0", "ads.lab", "0.0.0.0 ads.lab", ""},
		{"10.0.0", "nas", "", "ip"},
		{"10.0.0.5/24", "nas", "", "ip"},
		{"fe80::1%eth0", "nas", "", "ip"},
		{"10.0.0.5 10.0.0.6", "nas", "", "ip"},
		{"", "nas", "", "ip"},
		{"10.0.0.5", "nas lab", "", "hostname"},
		{"10.0.0.5", "nas.lab # x", "", "hostname"},
		{"10.0.0.5", "nas\nlab", "", "hostname"},
		{"10.0.0.5", "", "", "hostname"},
	}
	for _, tt := range tests {
		h, err := NewHost(tt.ip, tt.hostname)
		var fe *FieldError
		switch {
		case tt.field == "" && err != nil:
			t.Errorf("NewHost(%q, %q): %v", tt.ip, tt.hostname, err)
		case tt.field != "" && (!errors.As(err, &fe) || fe.Field != tt.field):
			t.Errorf("NewHost(%q, %q) = %v, want an error for %s", tt.ip, tt.hostname, err, tt.field)
		case tt.field == "":
			if h.Value != tt.value {
				t.Errorf("NewHost(%q, %q) = %q, want %q", tt.ip, tt.hostname, h.Value, tt.value)
			}
			if p := ParseHost(h.Value); p.Key != h.Key || len(p.Marks) != 0 || !p.Writable() {
				t.Errorf("NewHost(%q, %q): %q reads back as key %q marks %q, built key %q", tt.ip, tt.hostname,
					h.Value, p.Key, p.Marks, h.Key)
			}
		}
	}
}

func TestNewCNAME(t *testing.T) {
	tests := []struct {
		alias, target string
		ttl           *int
		value, field  string
	}{
		{"alias.lab", "nas.lab", nil, "alias.lab,nas.lab", ""},
		{"Alias.lab", "NAS.lab", ptr(300), "alias.lab,nas.lab,300", ""},
		{"alias", "nas", ptr(0), "alias,nas,0", ""},
		{"alias", "nas", ptr(MaxTTL), "alias,nas,86400", ""},
		{"alias", "nas", ptr(MaxTTL + 1), "", "ttl"},
		{"alias", "nas", ptr(-1), "", "ttl"},
		{"alias", "ALIAS", nil, "", "target"},
		{"a,b", "nas", nil, "", "alias"},
		{"alias", "nas,300", nil, "", "target"},
		{"alias", "nas #x", nil, "", "target"},
		{"", "nas", nil, "", "alias"},
		{"alias", "", nil, "", "target"},
	}
	for _, tt := range tests {
		c, err := NewCNAME(tt.alias, tt.target, tt.ttl)
		var fe *FieldError
		switch {
		case tt.field == "" && err != nil:
			t.Errorf("NewCNAME(%q, %q): %v", tt.alias, tt.target, err)
		case tt.field != "" && (!errors.As(err, &fe) || fe.Field != tt.field):
			t.Errorf("NewCNAME(%q, %q) = %v, want an error for %s", tt.alias, tt.target, err, tt.field)
		case tt.field == "":
			if c.Value != tt.value {
				t.Errorf("NewCNAME(%q, %q) = %q, want %q", tt.alias, tt.target, c.Value, tt.value)
			}
			if p := ParseCNAME(c.Value); p.Key != c.Key || len(p.Marks) != 0 || !p.Writable() {
				t.Errorf("NewCNAME(%q, %q): %q reads back as key %q marks %q", tt.alias, tt.target, c.Value, p.Key, p.Marks)
			}
		}
	}
	// The TTL is copied, so changing the caller's variable afterwards changes nothing.
	n := 60
	c, _ := NewCNAME("a", "b", &n)
	n = 1
	if *c.TTL != 60 {
		t.Errorf("TTL follows the caller's variable: %d", *c.TTL)
	}
}

func TestWritable(t *testing.T) {
	for value, want := range map[string]bool{
		"10.0.0.5 nas.lab":   true,
		"10.0.0.5  NAS.lab":  true,
		"10.0.0.5 my_host":   false,
		"10.0.0.5 a b":       false,
		"10.0.0.5 a # x":     false,
		"10.0.0.5":           false,
		"fd00::5 nas.lab":    true,
		"10.0.0.5 nas.lab.":  false,
		"10.0.0.5 -bad.lab":  false,
		"10.0.0.5 xn--a.lab": true,
	} {
		if got := ParseHost(value).Writable(); got != want {
			t.Errorf("host %q: Writable() = %v, want %v", value, got, want)
		}
	}
	for value, want := range map[string]bool{
		"alias.lab,nas.lab":        true,
		"alias.lab,nas.lab,300":    true,
		"alias.lab,nas.lab,999999": false,
		"a,b,nas":                  false,
		"alias,alias":              false,
		"alias,nas #x":             false,
		"alias,nas#lab":            false,
		"alias":                    false,
	} {
		if got := ParseCNAME(value).Writable(); got != want {
			t.Errorf("cname %q: Writable() = %v, want %v", value, got, want)
		}
	}
}

func TestDirectoryDomains(t *testing.T) {
	tests := []struct {
		baseDN string
		extra  []string
		want   []string
	}{
		{"DC=corp,DC=example,DC=com", nil, []string{"corp.example.com"}},
		{"OU=Staff,dc=Corp,dc=Example,dc=COM", nil, []string{"corp.example.com"}},
		{"CN=Users,DC=lab", []string{"home.arpa", "LAB", " other.lab "}, []string{"lab", "home.arpa", "other.lab"}},
		{"", []string{"home.arpa"}, []string{"home.arpa"}},
		{"OU=Staff,O=Example", nil, nil},
		{"not a dn", nil, nil},
		{"", nil, nil},
	}
	for _, tt := range tests {
		if got := DirectoryDomains(tt.baseDN, tt.extra); !slices.Equal(got, tt.want) {
			t.Errorf("DirectoryDomains(%q, %q) = %q, want %q", tt.baseDN, tt.extra, got, tt.want)
		}
	}
}

func TestUnderDomain(t *testing.T) {
	domains := []string{"corp.example.com", "home.arpa"}
	tests := []struct {
		name, want string
		ok         bool
	}{
		{"corp.example.com", "corp.example.com", true},
		{"DC1.Corp.Example.com", "corp.example.com", true},
		{"nas.home.arpa", "home.arpa", true},
		{"notcorp.example.com", "", false},
		{"example.com", "", false},
		{"nas.lab", "", false},
		{"home.arpa.lab", "", false},
	}
	for _, tt := range tests {
		got, ok := UnderDomain(tt.name, domains)
		if got != tt.want || ok != tt.ok {
			t.Errorf("UnderDomain(%q) = %q, %v; want %q, %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
	if _, ok := UnderDomain("nas.lab", nil); ok {
		t.Error("no domains matched something")
	}
}

func TestCheckExtraDomains(t *testing.T) {
	got, err := CheckExtraDomains([]string{"Home.arpa", "lab", "home.arpa"})
	if err != nil || !slices.Equal(got, []string{"home.arpa", "lab"}) {
		t.Errorf("got %q, %v", got, err)
	}
	if got, err := CheckExtraDomains(nil); err != nil || len(got) != 0 || got == nil {
		t.Errorf("nil: got %#v, %v; want an empty list", got, err)
	}
	var fe *FieldError
	if _, err := CheckExtraDomains([]string{"ok.lab", "bad domain"}); !errors.As(err, &fe) || fe.Field != "localdns_extra_domains" {
		t.Errorf("a bad domain: %v", err)
	}
	many := make([]string, MaxExtraDomains+1)
	for i := range many {
		many[i] = "d" + strings.Repeat("x", i) + ".lab"
	}
	if _, err := CheckExtraDomains(many); err == nil {
		t.Error("too many domains accepted")
	}
}
