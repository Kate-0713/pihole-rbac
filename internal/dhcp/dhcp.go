// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dhcp holds the app's rules for a Pi-hole's DHCP service: the checks on its settings, the lease time, and
// reading and building the static lease strings Pi-hole keeps in its dhcp.hosts config array.
//
// FTL checks DHCP settings as a whole when it writes dnsmasq's config, and only while DHCP is on. Static leases are
// worse: FTL's only check on a dhcp.hosts string is that it has no line break, and it writes the string into
// dnsmasq's config as a dhcp-host= line, again only while DHCP is on. So the app builds every string it sends from
// checked fields, and only ever sends a string it didn't build to delete one it has just read. The format Pi-hole
// accepts is
//
//	[<hwaddr>][,id:<client_id>|*][,set:<tag>][,tag:<tag>][,<ipaddr>][,<hostname>][,<lease_time>][,ignore]
//
// and the app writes "<mac>,<ip>" or "<mac>,<ip>,<hostname>" and nothing else.
package dhcp

import (
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/localdns"
)

const (
	// MinLeaseTime is dnsmasq's documented minimum lease time.
	MinLeaseTime = 2 * time.Minute
	// MaxLeaseTime is the longest lease time the app writes.
	MaxLeaseTime = 365 * 24 * time.Hour
)

// Marks on a static lease the app couldn't have written, as Static.Marks.
const (
	MarkExtraFields  = "extra_fields"  // a lease time, tag, client ID, ignore, or more than one address or name
	MarkMultipleMACs = "multiple_macs" // several hardware addresses
	MarkIPv6         = "ipv6"          // an IPv6 address
	MarkNoMAC        = "no_mac"        // no hardware address (a client ID, say, in its place)
	MarkUnparsed     = "unparsed"      // the string doesn't parse as a static lease at all
)

// FieldError is a value the app won't write. It is the same type Local DNS's checks return, so handlers turn both
// into a 400 validation_failed the same way.
type FieldError = localdns.FieldError

func refuse(field, msg string) error { return &FieldError{Field: field, Message: msg} }

// Settings is the part of a Pi-hole's dhcp config the app manages, as Pi-hole holds it: addresses as strings, empty
// when unset.
type Settings struct {
	Active               bool
	Start, End, Router   string
	Netmask              string
	LeaseTime            string
	IPv6                 bool
	RapidCommit          bool
	MultiDNS             bool
	IgnoreUnknownClients bool
}

var leaseTimeRE = regexp.MustCompile(`^([0-9]{1,9})([smhdw]?)$`)

// CheckLeaseTime checks a lease time from the request field named field and returns it as it will be written:
// trimmed and lowercased. It is seconds, or a number with m, h, d or w, between two minutes and 365 days. Empty is
// allowed and means dnsmasq's default. "infinite" is refused: a device that has gone away never gives its address
// back.
func CheckLeaseTime(field, s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if s == "infinite" {
		return "", refuse(field, "Infinite leases aren't allowed: an address would never come back from a device that has gone")
	}
	m := leaseTimeRE.FindStringSubmatch(s)
	if m == nil {
		return "", refuse(field, "The lease time must be a number of seconds, or a number followed by m, h, d or w (45m, 12h, 2d, 1w)")
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	unit := map[string]time.Duration{"": time.Second, "s": time.Second, "m": time.Minute, "h": time.Hour,
		"d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	d := time.Duration(n) * unit
	switch {
	case d < MinLeaseTime:
		return "", refuse(field, "The lease time must be at least 2 minutes")
	case d > MaxLeaseTime:
		return "", refuse(field, "The lease time must be at most 365 days")
	}
	return s, nil
}

// checkIPv4 parses an address the DHCP service could hand out or point at: IPv4, and not unspecified, loopback,
// multicast or the limited broadcast address.
func checkIPv4(field, v string) (netip.Addr, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	switch {
	case err != nil || !a.Is4():
		return netip.Addr{}, refuse(field, "The address isn't a valid IPv4 address")
	case a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return netip.Addr{}, refuse(field, "The address can't be used by a device")
	}
	return a, nil
}

// maskBits is the prefix length of a netmask, or -1 if it isn't a contiguous mask of 1 to 30 bits.
func maskBits(a netip.Addr) int {
	b := a.As4()
	m := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	inv := ^m
	if m == 0 || inv&(inv+1) != 0 {
		return -1
	}
	n := 0
	for ; m&0x80000000 != 0; m <<= 1 {
		n++
	}
	if n > 30 {
		return -1
	}
	return n
}

func classfulBits(a netip.Addr) int {
	switch b := a.As4()[0]; {
	case b&0x80 == 0:
		return 8
	case b&0xC0 == 0x80:
		return 16
	}
	return 24
}

// Subnet is the subnet s serves: from its netmask, or, with none, from the class of the start address, as FTL does
// (dnsmasq would use the interface's, which the app can't see). guessed says which. ok is false when there is
// nothing to work it out from, or the values don't parse.
func Subnet(s Settings) (p netip.Prefix, guessed, ok bool) {
	start, err := netip.ParseAddr(strings.TrimSpace(s.Start))
	if err != nil || !start.Is4() {
		return netip.Prefix{}, false, false
	}
	bits, guessed := classfulBits(start), true
	if nm := strings.TrimSpace(s.Netmask); nm != "" {
		a, err := netip.ParseAddr(nm)
		if err != nil || !a.Is4() || maskBits(a) < 0 {
			return netip.Prefix{}, false, false
		}
		bits, guessed = maskBits(a), false
	}
	return netip.PrefixFrom(start, bits).Masked(), guessed, true
}

// notHostAddr says why addr can't be given to a client in p: it is the subnet's network or broadcast address.
func notHostAddr(addr netip.Addr, p netip.Prefix) string {
	if addr == p.Addr() {
		return "is the network address of the subnet"
	}
	if addr == broadcast(p) {
		return "is the broadcast address of the subnet"
	}
	return ""
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	for i := p.Bits(); i < 32; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom4(b)
}

// CheckSettings checks the settings as they will be once a change is applied, as FTL will: the lease time and
// every address that is set must parse; and with DHCP on, the start, end and router must be set, none of them the
// subnet's network or broadcast address, the start not after the end, the router outside the range, and all three
// in the subnet. Errors are *FieldError for the fields "start", "end", "router", "netmask" and "lease_time".
func CheckSettings(s Settings) error {
	if _, err := CheckLeaseTime("lease_time", s.LeaseTime); err != nil {
		return err
	}
	addrs := map[string]netip.Addr{}
	for _, f := range []struct{ field, v string }{{"start", s.Start}, {"end", s.End}, {"router", s.Router}} {
		if strings.TrimSpace(f.v) == "" {
			if s.Active {
				return refuse(f.field, "This must be set while DHCP is on")
			}
			continue
		}
		a, err := checkIPv4(f.field, f.v)
		if err != nil {
			return err
		}
		addrs[f.field] = a
	}
	if nm := strings.TrimSpace(s.Netmask); nm != "" {
		a, err := netip.ParseAddr(nm)
		if err != nil || !a.Is4() || maskBits(a) < 0 {
			return refuse("netmask", "The netmask isn't a valid IPv4 netmask")
		}
	}
	if !s.Active {
		return nil
	}
	p, _, ok := Subnet(s)
	if !ok {
		return refuse("netmask", "The subnet can't be worked out")
	}
	for _, f := range []string{"start", "end", "router"} {
		a := addrs[f]
		if !p.Contains(a) {
			return refuse(f, "The address isn't in the subnet "+p.String())
		}
		if why := notHostAddr(a, p); why != "" {
			return refuse(f, "The address "+why)
		}
	}
	if addrs["start"].Compare(addrs["end"]) > 0 {
		return refuse("start", "The start of the range is after its end")
	}
	if r := addrs["router"]; r.Compare(addrs["start"]) >= 0 && r.Compare(addrs["end"]) <= 0 {
		return refuse("router", "The router's address is inside the range, which could hand it to a device")
	}
	return nil
}

// Static is a static lease as Pi-hole holds it. Value is Pi-hole's string exactly, which is what deleting it needs.
// For an entry that doesn't parse at all only Value, Key and Marks are set. MAC is lowercase with colons, IP the
// canonical IPv4 address; both are the first of each in the string, whatever else it holds.
type Static struct {
	Value    string
	MAC      string
	IP       string
	Hostname string
	Marks    []string
	Key      string
}

// Writable says whether the app could have written this entry, so it may be changed rather than only deleted.
func (s Static) Writable() bool { return len(s.Marks) == 0 }

var timeFieldRE = regexp.MustCompile(`^[0-9]+[smhdw]?$`)

// reserved says whether a word would be read by dnsmasq as something other than a hostname in a dhcp-host line.
func reserved(w string) bool {
	return w == "ignore" || w == "infinite" || timeFieldRE.MatchString(w)
}

// StaticKey is what matches a static lease: its hardware address and IP address.
func StaticKey(mac, ip string) string { return mac + "|" + ip }

// ParseStatic reads a dhcp.hosts string. Anything it can't make sense of is marked MarkUnparsed, and its key is the
// string itself.
func ParseStatic(value string) Static {
	unparsed := func() Static { return Static{Value: value, Marks: []string{MarkUnparsed}, Key: value} }
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
		return unparsed()
	}
	var macs, ips, names []string
	extra, v6 := false, false
	for _, f := range strings.Split(value, ",") {
		f = strings.TrimSpace(f)
		lower := strings.ToLower(f)
		switch {
		case f == "":
			return unparsed()
		case isMAC(f):
			hw, _ := net.ParseMAC(f)
			macs = append(macs, hw.String())
		case strings.HasPrefix(lower, "id:"), strings.HasPrefix(lower, "set:"), strings.HasPrefix(lower, "tag:"),
			lower == "ignore", lower == "infinite", timeFieldRE.MatchString(lower):
			extra = true
		case strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]"):
			v6 = true
		case isIPv4(f):
			a, _ := netip.ParseAddr(f)
			ips = append(ips, a.String())
		default:
			if _, err := localdns.CheckName("hostname", f); err != nil || strings.Contains(f, ".") {
				return unparsed()
			}
			names = append(names, strings.ToLower(f))
		}
	}
	s := Static{Value: value}
	if len(macs) > 0 {
		s.MAC = macs[0]
	}
	if len(ips) > 0 {
		s.IP = ips[0]
	}
	if len(names) > 0 {
		s.Hostname = names[0]
	}
	switch {
	case len(macs) > 1:
		s.Marks = append(s.Marks, MarkMultipleMACs)
	case len(macs) == 0:
		s.Marks = append(s.Marks, MarkNoMAC)
	}
	if v6 {
		s.Marks = append(s.Marks, MarkIPv6)
	}
	if extra || len(ips) > 1 || len(names) > 1 {
		s.Marks = append(s.Marks, MarkExtraFields)
	}
	if s.MAC == "" && s.IP == "" {
		s.Key = value
	} else {
		s.Key = StaticKey(s.MAC, s.IP)
	}
	return s
}

func isMAC(f string) bool {
	hw, err := net.ParseMAC(f)
	return err == nil && len(hw) == 6
}

func isIPv4(f string) bool {
	a, err := netip.ParseAddr(f)
	return err == nil && a.Is4()
}

// NewStatic builds the static lease the app writes for mac, ip and the optional hostname: "<mac>,<ip>" or
// "<mac>,<ip>,<hostname>", with the hardware address lowercase with colons, the address canonical and the hostname
// lowercased. When settings is given and gives a subnet, the address must be a host address in it. Errors are
// *FieldError for the fields "mac", "ip" and "hostname".
func NewStatic(mac, ip, hostname string, settings *Settings) (Static, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	switch {
	case err != nil || len(hw) != 6:
		return Static{}, refuse("mac", "The hardware address must be six octets, like aa:bb:cc:dd:ee:ff")
	case hw[0]&1 != 0:
		return Static{}, refuse("mac", "The hardware address is a group address, which no device has")
	case hw.String() == "00:00:00:00:00:00":
		return Static{}, refuse("mac", "The hardware address is all zeros")
	}
	a, err := checkIPv4("ip", ip)
	if err != nil {
		return Static{}, err
	}
	if settings != nil {
		if p, _, ok := Subnet(*settings); ok {
			if !p.Contains(a) {
				return Static{}, refuse("ip", "The address isn't in the DHCP subnet "+p.String())
			}
			if why := notHostAddr(a, p); why != "" {
				return Static{}, refuse("ip", "The address "+why)
			}
		}
	}
	s := Static{MAC: hw.String(), IP: a.String()}
	s.Value = s.MAC + "," + s.IP
	if strings.TrimSpace(hostname) != "" {
		name, err := localdns.CheckName("hostname", hostname)
		switch {
		case err != nil:
			return Static{}, err
		case strings.Contains(name, "."):
			return Static{}, refuse("hostname", "The name must be a single label, with no dots")
		case reserved(name):
			return Static{}, refuse("hostname", "dnsmasq would read this name as a lease time or option, not a name")
		}
		s.Hostname = name
		s.Value += "," + name
	}
	s.Key = StaticKey(s.MAC, s.IP)
	return s, nil
}

// Conflict finds a static lease in existing that has the same hardware address or the same IP address as a lease
// about to be added, and says which field clashes. Entries that couldn't be read don't count, since nothing in them
// can be compared. To check a change, leave the lease being replaced out of existing.
func Conflict(existing []Static, mac, ip string) (field string, other Static, found bool) {
	for _, e := range existing {
		switch {
		case slices.Contains(e.Marks, MarkUnparsed):
		case mac != "" && e.MAC == mac:
			return "mac", e, true
		case ip != "" && e.IP == ip:
			return "ip", e, true
		}
	}
	return "", Static{}, false
}

// Normalize writes the settings as they will be sent to Pi-hole: addresses that parse in their canonical form,
// the lease time trimmed and lowercased, empty values empty. A value that doesn't parse is left as it was so
// CheckSettings can refuse it by field; the values sent are never the request's own text once they pass it.
func Normalize(s Settings) Settings {
	canon := func(v string) string {
		v = strings.TrimSpace(v)
		if a, err := netip.ParseAddr(v); err == nil && a.Is4() {
			return a.String()
		}
		return v
	}
	s.Start, s.End, s.Router, s.Netmask = canon(s.Start), canon(s.End), canon(s.Router), canon(s.Netmask)
	if lt, err := CheckLeaseTime("lease_time", s.LeaseTime); err == nil {
		s.LeaseTime = lt
	}
	return s
}
