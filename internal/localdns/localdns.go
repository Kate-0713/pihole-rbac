// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package localdns holds the app's rules for Pi-hole's local DNS records: reading the strings Pi-hole keeps in its
// dns.hosts and dns.cnameRecords config arrays, the key that matches a record across Pi-holes, building the strings
// the app writes, and the checks on what a person may add.
//
// Pi-hole stores a host record as "IP HOSTNAME [HOSTNAME …]" and a CNAME as "<cname>,[<cname>,…]<target>[,<TTL>]",
// either of which may end in a # comment. FTL checks host records fairly well, but not the names in a CNAME or its
// TTL, so the app builds every string it sends from checked fields, and only ever sends a string it didn't build to
// delete one it has just read.
package localdns

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

const (
	// MaxNameLength caps a hostname, a CNAME's alias or target, or a directory domain, in characters.
	MaxNameLength = 253
	// MaxLabelLength caps one label of a name.
	MaxLabelLength = 63
	// MaxTTL is the longest TTL, in seconds, the app writes on a CNAME.
	MaxTTL = 86400
	// MaxExtraDomains caps the extra directory domains in the general settings.
	MaxExtraDomains = 20
)

// Marks on a record the app couldn't have written, as Host.Marks and CNAME.Marks.
const (
	MarkMultipleNames = "multiple_names" // several hostnames on a host record, or several aliases on a CNAME
	MarkComment       = "comment"        // a # comment
	MarkUnparsed      = "unparsed"       // the string doesn't parse as a record at all
)

// FieldError is a value the app won't write. Field is the request field it came from; Message is a sentence without
// its full stop, fit to show to the person who sent it.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Message }

func refuse(field, format string, args ...any) error {
	return &FieldError{Field: field, Message: fmt.Sprintf(format, args...)}
}

// Host is a host record as Pi-hole holds it. Value is Pi-hole's string exactly, which is what deleting it needs.
// For an unparsed record only Value, Key and Marks are set.
type Host struct {
	Value     string
	IP        netip.Addr
	Hostnames []string // as written in Value
	Comment   string   // the text after #, trimmed
	Marks     []string
	Key       string
}

// CNAME is a CNAME record as Pi-hole holds it. TTL is nil when the record has none. For an unparsed record only
// Value, Key and Marks are set.
type CNAME struct {
	Value   string
	Aliases []string // as written in Value
	Target  string
	TTL     *int
	Comment string
	Marks   []string
	Key     string
}

// isHostSpace is the whitespace FTL splits a host record on.
func isHostSpace(r rune) bool { return r == ' ' || r == '\t' }

func hasLineBreak(s string) bool { return strings.ContainsAny(s, "\r\n") }

// ParseHost reads one of Pi-hole's dns.hosts strings the way FTL does: an address, then hostnames separated by spaces
// or tabs, up to a field that starts with #, which begins a comment. The key is the address in its canonical form and
// the hostnames lowercased, in order, so "10.0.0.5  NAS.lab" and "10.0.0.5 nas.lab" are the same record.
func ParseHost(value string) Host {
	h := Host{Value: value}
	if hasLineBreak(value) {
		return unparsedHost(h)
	}
	fields := strings.FieldsFunc(value, isHostSpace)
	if len(fields) < 2 {
		return unparsedHost(h)
	}
	ip, err := netip.ParseAddr(fields[0])
	if err != nil || ip.Zone() != "" {
		return unparsedHost(h)
	}
	h.IP = ip
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "#") {
			h.Comment = strings.TrimSpace(value[commentStart(value)+1:])
			h.Marks = append(h.Marks, MarkComment)
			break
		}
		h.Hostnames = append(h.Hostnames, f)
	}
	if len(h.Hostnames) == 0 {
		return unparsedHost(Host{Value: value})
	}
	if len(h.Hostnames) > 1 {
		h.Marks = append([]string{MarkMultipleNames}, h.Marks...)
	}
	h.Key = HostKey(h.IP, h.Hostnames)
	return h
}

func unparsedHost(h Host) Host {
	h.Marks = []string{MarkUnparsed}
	h.Key = h.Value
	return h
}

// HostKey is the key of a host record with ip and hostnames.
func HostKey(ip netip.Addr, hostnames []string) string {
	var b strings.Builder
	b.WriteString(ip.String())
	for _, n := range hostnames {
		b.WriteByte(' ')
		b.WriteString(strings.ToLower(n))
	}
	return b.String()
}

// ParseCNAME reads one of Pi-hole's dns.cnameRecords strings the way FTL and dnsmasq do: anything from a # at the
// start or after whitespace is a comment, the rest is split on commas with the whitespace around each part dropped,
// and a last part that is a number is the TTL. The key is the names lowercased, in order, then the TTL.
func ParseCNAME(value string) CNAME {
	c := CNAME{Value: value}
	if hasLineBreak(value) {
		return unparsedCNAME(c)
	}
	body := value
	if i := commentStart(value); i >= 0 {
		body = value[:i]
		c.Comment = strings.TrimSpace(value[i+1:])
		c.Marks = append(c.Marks, MarkComment)
	}
	parts := strings.Split(body, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.IndexFunc(p, unicode.IsSpace) >= 0 {
			return unparsedCNAME(CNAME{Value: value})
		}
		parts[i] = p
	}
	if n := len(parts); n >= 3 && isDigits(parts[n-1]) {
		ttl, err := strconv.Atoi(parts[n-1])
		if err != nil {
			return unparsedCNAME(CNAME{Value: value})
		}
		c.TTL = &ttl
		parts = parts[:n-1]
	}
	if len(parts) < 2 {
		return unparsedCNAME(CNAME{Value: value})
	}
	c.Aliases, c.Target = parts[:len(parts)-1], parts[len(parts)-1]
	if len(c.Aliases) > 1 {
		c.Marks = append([]string{MarkMultipleNames}, c.Marks...)
	}
	c.Key = CNAMEKey(c.Aliases, c.Target, c.TTL)
	return c
}

// commentStart is where a comment starts, as FTL's cut_comment finds it: a # at the start or after whitespace. It is
// -1 for no comment. In a host record that is the same # as the first field starting with one.
func commentStart(s string) int {
	for i, r := range s {
		if r == '#' && (i == 0 || unicode.IsSpace(rune(s[i-1]))) {
			return i
		}
	}
	return -1
}

func isDigits(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

func unparsedCNAME(c CNAME) CNAME {
	c.Marks = []string{MarkUnparsed}
	c.Key = c.Value
	return c
}

// CNAMEKey is the key of a CNAME with aliases, target and ttl.
func CNAMEKey(aliases []string, target string, ttl *int) string {
	names := make([]string, 0, len(aliases)+1)
	for _, a := range aliases {
		names = append(names, strings.ToLower(a))
	}
	names = append(names, strings.ToLower(target))
	key := strings.Join(names, ",")
	if ttl != nil {
		key += "," + strconv.Itoa(*ttl)
	}
	return key
}

// CheckName checks a hostname, a CNAME's alias or target, or a directory domain, from the request field named field,
// and returns it lowercased. A name is ASCII letters, digits, hyphens and dots, in labels of 1 to 63 characters that
// don't start or end with a hyphen, at most 253 characters in all, with no trailing dot. A single label (nas) is a
// name. Underscores, which FTL accepts, are refused: they aren't valid in a hostname. Surrounding whitespace is
// dropped.
func CheckName(field, name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", refuse(field, "The name is empty")
	case len(name) > MaxNameLength:
		return "", refuse(field, "The name is longer than %d characters", MaxNameLength)
	case strings.HasSuffix(name, "."):
		return "", refuse(field, "The name ends with a dot")
	}
	for _, r := range name {
		if r > unicode.MaxASCII {
			return "", refuse(field, "The name has characters other than letters, digits, hyphens and dots in it (an internationalised name needs its xn-- form)")
		}
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return "", refuse(field, "The name has characters other than letters, digits, hyphens and dots in it")
		}
	}
	for _, label := range strings.Split(name, ".") {
		switch {
		case label == "":
			return "", refuse(field, "The name has an empty label (two dots together, or a dot at the start)")
		case len(label) > MaxLabelLength:
			return "", refuse(field, "A part of the name between dots is longer than %d characters", MaxLabelLength)
		case strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-"):
			return "", refuse(field, "A part of the name between dots starts or ends with a hyphen")
		}
	}
	return strings.ToLower(name), nil
}

// CheckIP checks the address of a host record from the request field named field: IPv4 or IPv6, without a zone.
func CheckIP(field, ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, refuse(field, "The address isn't a valid IPv4 or IPv6 address")
	}
	if a.Zone() != "" {
		return netip.Addr{}, refuse(field, "The address has a zone (%%…), which Pi-hole doesn't accept")
	}
	return a, nil
}

// NewHost builds the host record the app writes for ip and hostname: "<ip> <hostname>", with the address in its
// canonical form and the hostname lowercased. Errors are *FieldError for the fields "ip" and "hostname".
func NewHost(ip, hostname string) (Host, error) {
	a, err := CheckIP("ip", ip)
	if err != nil {
		return Host{}, err
	}
	name, err := CheckName("hostname", hostname)
	if err != nil {
		return Host{}, err
	}
	return Host{Value: a.String() + " " + name, IP: a, Hostnames: []string{name}, Key: HostKey(a, []string{name})}, nil
}

// NewCNAME builds the CNAME the app writes: "<alias>,<target>" or "<alias>,<target>,<ttl>", names lowercased. The
// alias and target must differ, and a TTL is 0 to MaxTTL seconds. Errors are *FieldError for "alias", "target" and
// "ttl".
func NewCNAME(alias, target string, ttl *int) (CNAME, error) {
	a, err := CheckName("alias", alias)
	if err != nil {
		return CNAME{}, err
	}
	t, err := CheckName("target", target)
	if err != nil {
		return CNAME{}, err
	}
	if a == t {
		return CNAME{}, refuse("target", "The target is the same as the alias")
	}
	value := a + "," + t
	if ttl != nil {
		if *ttl < 0 || *ttl > MaxTTL {
			return CNAME{}, refuse("ttl", "The TTL must be between 0 and %d seconds", MaxTTL)
		}
		v := *ttl
		ttl = &v
		value += "," + strconv.Itoa(v)
	}
	return CNAME{Value: value, Aliases: []string{a}, Target: t, TTL: ttl, Key: CNAMEKey([]string{a}, t, ttl)}, nil
}

// Writable reports whether the app could have written h itself: no marks, and fields that pass the app's checks.
// Reconcile copies only records like this to other members.
func (h Host) Writable() bool {
	if len(h.Marks) > 0 {
		return false
	}
	built, err := NewHost(h.IP.String(), h.Hostnames[0])
	return err == nil && built.Key == h.Key
}

// Writable reports whether the app could have written c itself.
func (c CNAME) Writable() bool {
	if len(c.Marks) > 0 {
		return false
	}
	built, err := NewCNAME(c.Aliases[0], c.Target, c.TTL)
	return err == nil && built.Key == c.Key
}

// DirectoryDomains are the domains a record's name is checked against: the DC= parts of the LDAP base DN, joined
// with dots (DC=corp,DC=example,DC=com gives corp.example.com), when baseDN has any, and the extra domains, all
// lowercased, without duplicates. A base DN that doesn't parse, or has no DC= parts, adds nothing.
func DirectoryDomains(baseDN string, extra []string) []string {
	var out []string
	if d := baseDNDomain(baseDN); d != "" {
		out = append(out, d)
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func baseDNDomain(baseDN string) string {
	if strings.TrimSpace(baseDN) == "" {
		return ""
	}
	dn, err := ldap.ParseDN(baseDN)
	if err != nil {
		return ""
	}
	var labels []string
	for _, rdn := range dn.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "dc") {
				labels = append(labels, strings.ToLower(a.Value))
			}
		}
	}
	return strings.Join(labels, ".")
}

// UnderDomain returns the first of domains that name is, or falls under, and whether there is one. name is compared
// lowercased.
func UnderDomain(name string, domains []string) (string, bool) {
	name = strings.ToLower(name)
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return d, true
		}
	}
	return "", false
}

// CheckExtraDomains checks the extra directory domains from the general settings: at most MaxExtraDomains, each a
// valid name. It returns them lowercased, without duplicates, in the order given. Errors are *FieldError for the
// field "localdns_extra_domains".
func CheckExtraDomains(domains []string) ([]string, error) {
	const field = "localdns_extra_domains"
	if len(domains) > MaxExtraDomains {
		return nil, refuse(field, "There can be at most %d extra directory domains", MaxExtraDomains)
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		n, err := CheckName(field, d)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}
