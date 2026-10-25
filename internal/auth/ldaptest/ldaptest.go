// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ldaptest is a small LDAP server for tests and the e2e server: enough of LDAPv3 for what pihole-rbac asks a
// directory (simple binds, and searches with equality, presence, AND, OR and NOT filters), over plain TCP. Entries
// live in memory. It is not part of the app.
package ldaptest

import (
	"io"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Entry is one directory entry. Attribute names are matched ignoring case.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Server is a running fake directory.
type Server struct {
	ln net.Listener

	mu        sync.Mutex
	entries   []Entry
	passwords map[string]string // by normalised DN
	binds     int               // successful non-anonymous binds
	wg        sync.WaitGroup
}

// Start listens on addr ("127.0.0.1:0" for any free port) and serves until Close.
func Start(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, passwords: map[string]string{}}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// URL is the ldap:// URL to give the app.
func (s *Server) URL() string { return "ldap://" + s.ln.Addr().String() }

// Close stops the server and waits for its connections to end.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

// Add adds an entry, and a password to bind as it with if password isn't empty.
func (s *Server) Add(dn, password string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lower := map[string][]string{}
	for k, v := range attrs {
		lower[strings.ToLower(k)] = v
	}
	s.entries = append(s.entries, Entry{DN: dn, Attrs: lower})
	if password != "" {
		s.passwords[norm(dn)] = password
	}
}

// SetPassword changes the password of dn.
func (s *Server) SetPassword(dn, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[norm(dn)] = password
}

// Binds returns how many binds with a password have succeeded, so a test can tell whether the app asked.
func (s *Server) Binds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c)
		}()
	}
}

// LDAP result codes and protocol operation tags used here.
const (
	resultSuccess          = 0
	resultProtocolError    = 2
	resultNoSuchObject     = 32
	resultInvalidCreds     = 49
	resultInsufficientAuth = 50
	resultUnwilling        = 53

	opBindRequest    = 0
	opBindResponse   = 1
	opUnbindRequest  = 2
	opSearchRequest  = 3
	opSearchEntry    = 4
	opSearchDone     = 5
	opAbandonRequest = 16
)

func (s *Server) handle(c net.Conn) {
	bound := false
	for {
		p, err := ber.ReadPacket(c)
		if err != nil {
			return // closed, or garbage: either way the connection is done
		}
		if len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		if op.ClassType != ber.ClassApplication {
			return
		}
		switch op.Tag {
		case opBindRequest:
			code := s.bind(op)
			bound = code == resultSuccess && bindHasPassword(op)
			write(c, response(id, opBindResponse, code, ""))
		case opSearchRequest:
			if !bound {
				write(c, response(id, opSearchDone, resultInsufficientAuth, "bind first"))
				continue
			}
			s.search(c, id, op)
		case opUnbindRequest:
			return
		case opAbandonRequest:
		default:
			write(c, response(id, opSearchDone, resultUnwilling, "not supported"))
		}
	}
}

func bindHasPassword(op *ber.Packet) bool {
	return len(op.Children) >= 3 && op.Children[2].Data.Len() > 0
}

// bind checks a simple bind. An empty password is an anonymous bind, which succeeds but allows no searches.
func (s *Server) bind(op *ber.Packet) int64 {
	if len(op.Children) < 3 || op.Children[2].ClassType != ber.ClassContext || op.Children[2].Tag != 0 {
		return resultProtocolError
	}
	dn, password := str(op.Children[1]), op.Children[2].Data.String()
	if password == "" {
		return resultSuccess
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if want, ok := s.passwords[norm(dn)]; ok && want == password {
		s.binds++
		return resultSuccess
	}
	return resultInvalidCreds
}

func (s *Server) search(c net.Conn, id int64, op *ber.Packet) {
	if len(op.Children) < 8 {
		write(c, response(id, opSearchDone, resultProtocolError, "malformed search"))
		return
	}
	base := str(op.Children[0])
	scope, _ := op.Children[1].Value.(int64)
	filter := op.Children[6]
	var wanted []string
	for _, a := range op.Children[7].Children {
		wanted = append(wanted, strings.ToLower(str(a)))
	}

	baseDN, err := ldap.ParseDN(base)
	if err != nil {
		write(c, response(id, opSearchDone, resultProtocolError, "bad base DN"))
		return
	}
	s.mu.Lock()
	entries := append([]Entry(nil), s.entries...)
	s.mu.Unlock()

	baseExists := false
	var found []Entry
	for _, e := range entries {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil {
			continue
		}
		same := dn.EqualFold(baseDN)
		baseExists = baseExists || same
		in := same
		if scope == 1 {
			in = !same && baseDN.AncestorOfFold(dn) && len(dn.RDNs) == len(baseDN.RDNs)+1
		} else if scope == 2 {
			in = same || baseDN.AncestorOfFold(dn)
		}
		if in && matches(filter, e) {
			found = append(found, e)
		}
	}
	if !baseExists && !s.hasAncestorOf(entries, baseDN) {
		write(c, response(id, opSearchDone, resultNoSuchObject, ""))
		return
	}
	for _, e := range found {
		write(c, entry(id, e, wanted))
	}
	write(c, response(id, opSearchDone, resultSuccess, ""))
}

// hasAncestorOf says whether some entry lies under dn, so a search based on an organisational DN that isn't itself an
// entry (dc=example,dc=com, say) still works, as on real servers whose naming context exists.
func (s *Server) hasAncestorOf(entries []Entry, dn *ldap.DN) bool {
	for _, e := range entries {
		if d, err := ldap.ParseDN(e.DN); err == nil && dn.AncestorOfFold(d) {
			return true
		}
	}
	return false
}

// matches evaluates a filter: and [0], or [1], not [2], equalityMatch [3] and present [7]. Anything else matches
// nothing. Values are compared ignoring case; a value that is a DN is compared as a DN.
func matches(f *ber.Packet, e Entry) bool {
	if f.ClassType != ber.ClassContext {
		return false
	}
	switch f.Tag {
	case 0:
		for _, c := range f.Children {
			if !matches(c, e) {
				return false
			}
		}
		return true
	case 1:
		for _, c := range f.Children {
			if matches(c, e) {
				return true
			}
		}
		return false
	case 2:
		return len(f.Children) == 1 && !matches(f.Children[0], e)
	case 3:
		if len(f.Children) != 2 {
			return false
		}
		attr, want := strings.ToLower(str(f.Children[0])), str(f.Children[1])
		if attr == "objectclass" && want == "*" {
			return true
		}
		for _, v := range e.Attrs[attr] {
			if equalValue(v, want) {
				return true
			}
		}
		return false
	case 7:
		attr := strings.ToLower(f.Data.String())
		return attr == "objectclass" || len(e.Attrs[attr]) > 0
	}
	return false
}

func equalValue(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	da, errA := ldap.ParseDN(a)
	db, errB := ldap.ParseDN(b)
	return errA == nil && errB == nil && len(da.RDNs) > 0 && da.EqualFold(db)
}

func norm(dn string) string {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(dn)
	}
	return strings.ToLower(d.String())
}

func str(p *ber.Packet) string {
	if v, ok := p.Value.(string); ok {
		return v
	}
	return p.Data.String()
}

func envelope(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "Message ID"))
	return p
}

func response(id int64, tag ber.Tag, code int64, message string) *ber.Packet {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "Result code"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "Diagnostic message"))
	p.AppendChild(op)
	return p
}

func entry(id int64, e Entry, wanted []string) *ber.Packet {
	p := envelope(id)
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, opSearchEntry, nil, "Search result entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "Object name"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, name := range wanted {
		vals, ok := e.Attrs[name]
		if !ok {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	p.AppendChild(op)
	return p
}

func write(w io.Writer, p *ber.Packet) {
	_, _ = w.Write(p.Bytes())
}

// Example fills s with a small directory under dc=example,dc=local: a service account, users and groups. It returns
// what tests need to know about it. Every password is its user's name followed by "-ldap-password".
func Example(s *Server) Fixture {
	f := Fixture{
		URL:          s.URL(),
		BaseDN:       "dc=example,dc=local",
		BindDN:       "cn=svc-pihole,ou=service,dc=example,dc=local",
		BindPassword: "svc-ldap-password",
		UserFilter:   "(uid=%s)",
		AdminGroup:   "cn=pihole-admins,ou=groups,dc=example,dc=local",
		StaffGroup:   "cn=pihole-staff,ou=groups,dc=example,dc=local",
		EmptyGroup:   "cn=nobody,ou=groups,dc=example,dc=local",
		Users: map[string]string{
			"lucy": "uid=lucy,ou=people,dc=example,dc=local",
			// mark sits deeper, as users in a real directory often do; the users page test needs a DN too long for its column.
			"mark": "uid=mark,ou=people,ou=headquarters,dc=example,dc=local",
			"nina": "uid=nina,ou=people,dc=example,dc=local",
		},
	}
	s.Add(f.BindDN, f.BindPassword, map[string][]string{"objectClass": {"person"}, "cn": {"svc-pihole"}})
	for name, dn := range f.Users {
		s.Add(dn, name+"-ldap-password", map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {name}})
	}
	s.Add(f.AdminGroup, "", map[string][]string{"objectClass": {"groupOfNames"}, "member": {f.Users["lucy"]}})
	s.Add(f.StaffGroup, "", map[string][]string{"objectClass": {"groupOfNames"}, "member": {f.Users["lucy"], f.Users["mark"]}})
	s.Add(f.EmptyGroup, "", map[string][]string{"objectClass": {"groupOfNames"}})
	return f
}

// Fixture describes the directory Example builds. nina is in no group.
type Fixture struct {
	URL          string            `json:"url"`
	BaseDN       string            `json:"base_dn"`
	BindDN       string            `json:"bind_dn"`
	BindPassword string            `json:"bind_password"`
	UserFilter   string            `json:"user_filter"`
	AdminGroup   string            `json:"admin_group"`
	StaffGroup   string            `json:"staff_group"`
	EmptyGroup   string            `json:"empty_group"`
	Users        map[string]string `json:"users"` // username to DN
}

// Password is the password of one of the Example users.
func (Fixture) Password(username string) string { return username + "-ldap-password" }
