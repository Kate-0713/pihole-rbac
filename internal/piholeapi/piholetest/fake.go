// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package piholetest is a fake Pi-hole v6 API for tests. It implements login, logout and session checks, and keeps
// blocking, domains, clients, groups, lists and the query log in memory, with the Pi-hole behaviours the app has to cope
// with: PUT creates an entry that doesn't exist, PUT without "enabled" enables the entry, a duplicate add is a 2xx
// with the item under processed.errors, and malformed input is a 400 with an error body. Tests add or override
// anything else with Handle.
package piholetest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Domain is an allow or deny list entry, as Pi-hole returns it.
type Domain struct {
	ID           int    `json:"id"`
	Domain       string `json:"domain"`
	Type         string `json:"type"`
	Kind         string `json:"kind"`
	Comment      string `json:"comment"`
	Groups       []int  `json:"groups"`
	Enabled      bool   `json:"enabled"`
	DateAdded    int64  `json:"date_added"`
	DateModified int64  `json:"date_modified"`
}

// Client is a configured client, as Pi-hole returns it.
type Client struct {
	ID           int    `json:"id"`
	Client       string `json:"client"`
	Name         string `json:"name"`
	Comment      string `json:"comment"`
	Groups       []int  `json:"groups"`
	DateAdded    int64  `json:"date_added"`
	DateModified int64  `json:"date_modified"`
}

// Group is a Pi-hole group.
type Group struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
}

// List is a subscribed list (an adlist).
type List struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
}

// Query is a query log entry.
type Query struct {
	ID     int     `json:"id"`
	Time   float64 `json:"time"`
	Type   string  `json:"type"`
	Domain string  `json:"domain"`
	Client struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	} `json:"client"`
	Status   string `json:"status"`
	DNSSEC   string `json:"dnssec"`
	Upstream string `json:"upstream"`
	Reply    struct {
		Type string  `json:"type"`
		Time float64 `json:"time"`
	} `json:"reply"`
}

// Server is a fake Pi-hole.
type Server struct {
	*httptest.Server

	password string

	mu       sync.Mutex
	validity int
	sessions map[string]bool
	logins   int
	logouts  int
	blocking bool
	timer    *float64
	domains  []Domain
	clients  []Client
	groups   []Group
	lists    []List
	queries  []Query // the in-memory log, newest first
	disk     []Query // the long-term database, newest first
	nextID   int
	now      int64
	requests []string
	handle   func(w http.ResponseWriter, r *http.Request) bool
}

// New starts a plain HTTP fake that accepts password. It is closed when the test ends.
func New(t testing.TB, password string) *Server {
	s := Start(password)
	t.Cleanup(s.Close)
	return s
}

// Start starts a plain HTTP fake outside a test, for the end-to-end test server. The caller closes it.
func Start(password string) *Server {
	s := newServer(password)
	s.Server = httptest.NewServer(s)
	return s
}

// NewTLS starts an HTTPS fake with httptest's self-signed certificate.
func NewTLS(t testing.TB, password string) *Server {
	s := newServer(password)
	s.Server = httptest.NewTLSServer(s)
	t.Cleanup(s.Close)
	return s
}

func newServer(password string) *Server {
	return &Server{
		password: password, validity: 1800, sessions: map[string]bool{}, blocking: true,
		groups: []Group{{ID: 0, Name: "Default", Comment: "The default group", Enabled: true}},
		nextID: 1, now: 1_790_000_000,
	}
}

// SetValidity sets the session lifetime, in seconds, that later logins report.
func (s *Server) SetValidity(seconds int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validity = seconds
}

// Handle installs a handler that runs, after the session check, before the built-in endpoints. It returns true if it
// handled the request.
func (s *Server) Handle(h func(w http.ResponseWriter, r *http.Request) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handle = h
}

// ForgetSessions drops every session, as a Pi-hole restart does.
func (s *Server) ForgetSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}

// Sessions returns how many sessions are open.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Logins returns how many logins succeeded.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Logouts returns how many sessions were ended with DELETE /api/auth.
func (s *Server) Logouts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logouts
}

// Requests returns "METHOD escaped-path" for every authenticated request so far, auth calls excluded.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Blocking reports whether blocking is on, and the timer last set (nil for none).
func (s *Server) Blocking() (bool, *float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocking, s.timer
}

// AddGroup adds a Pi-hole group and returns its ID.
func (s *Server) AddGroup(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.id()
	s.groups = append(s.groups, Group{ID: id, Name: name, Enabled: true})
	return id
}

// AddDomain adds a list entry directly and returns its ID. A nil Groups becomes the default group.
func (s *Server) AddDomain(d Domain) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	d.ID = s.id()
	if d.Groups == nil {
		d.Groups = []int{0}
	}
	d.DateAdded, d.DateModified = s.now, s.now
	s.domains = append(s.domains, d)
	return d.ID
}

// Domains returns the list entries.
func (s *Server) Domains() []Domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.domains)
}

// AddClient adds a client directly and returns its ID. A nil Groups becomes the default group.
func (s *Server) AddClient(c Client) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.ID = s.id()
	if c.Groups == nil {
		c.Groups = []int{0}
	}
	c.DateAdded, c.DateModified = s.now, s.now
	s.clients = append(s.clients, c)
	return c.ID
}

// Clients returns the clients.
func (s *Server) Clients() []Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.clients)
}

// AddList adds a subscribed list directly and returns its ID. A nil Groups becomes the default group.
func (s *Server) AddList(l List) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	l.ID = s.id()
	if l.Groups == nil {
		l.Groups = []int{0}
	}
	s.lists = append(s.lists, l)
	return l.ID
}

// Lists returns the subscribed lists.
func (s *Server) Lists() []List {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.lists)
}

// SetQueries replaces the in-memory query log, newest first.
func (s *Server) SetQueries(qs []Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = slices.Clone(qs)
}

// SetDiskQueries replaces the long-term database, which reads with disk=true see, newest first. Real Pi-holes keep
// the in-memory log there too, a minute or so behind; tests give it whatever they need.
func (s *Server) SetDiskQueries(qs []Query) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disk = slices.Clone(qs)
}

// id returns a new row ID. Called with s.mu held.
func (s *Server) id() int {
	id := s.nextID
	s.nextID++
	return id
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/auth" && r.Method == http.MethodPost:
		s.login(w, r)
		return
	case r.URL.Path == "/api/auth" && r.Method == http.MethodDelete:
		s.logout(w, r)
		return
	}

	s.mu.Lock()
	ok := s.sessions[r.Header.Get("X-FTL-SID")]
	handle := s.handle
	if ok {
		s.requests = append(s.requests, r.Method+" "+r.URL.EscapedPath())
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized", "Unauthorized"))
		return
	}
	if handle != nil && handle(w, r) {
		return
	}

	// Path segments after /api, unescaped one by one so an escaped slash in a domain or client stays in its segment.
	var seg []string
	for _, p := range strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/api/"), "/") {
		u, err := url.PathUnescape(p)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid path"))
			return
		}
		seg = append(seg, u)
	}
	route := r.Method + " " + seg[0]
	if len(seg) > 1 {
		route += "/" + seg[1]
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case route == "GET dns/blocking":
		writeJSON(w, http.StatusOK, s.blockingJSON())
	case route == "POST dns/blocking":
		var in struct {
			Blocking *bool    `json:"blocking"`
			Timer    *float64 `json:"timer"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Blocking == nil {
			writeJSON(w, http.StatusBadRequest, errBody("bad_request", "No \"blocking\" boolean in body"))
			return
		}
		s.blocking, s.timer = *in.Blocking, in.Timer
		writeJSON(w, http.StatusOK, s.blockingJSON())
	case route == "POST action/restartdns":
		writeJSON(w, http.StatusOK, map[string]any{"status": "restarting"})
	case route == "GET stats/summary":
		writeJSON(w, http.StatusOK, map[string]any{
			"queries": map[string]any{
				"total": 1000, "blocked": 250, "percent_blocked": 25.0, "unique_domains": 300,
				"forwarded": 500, "cached": 250, "status": map[string]int{"GRAVITY": 250}, "replies": map[string]int{"IP": 700},
			},
			"clients": map[string]int{"active": 5, "total": 8},
			"gravity": map[string]int{"domains_being_blocked": 123456},
		})
	case route == "GET stats/database":
		writeJSON(w, http.StatusOK, map[string]any{
			"sum_queries": 20000, "sum_blocked": 4000, "percent_blocked": 20.0, "total_clients": 9,
		})
	case route == "GET domains" && len(seg) == 1:
		writeJSON(w, http.StatusOK, map[string]any{"domains": s.domains})
	case strings.HasPrefix(route, "POST domains") && len(seg) == 3:
		s.postDomain(w, r, seg[1], seg[2])
	case strings.HasPrefix(route, "PUT domains") && len(seg) == 4:
		s.putDomain(w, r, seg[1], seg[2], seg[3])
	case strings.HasPrefix(route, "DELETE domains") && len(seg) == 4:
		i := s.findDomain(seg[3], seg[1], seg[2])
		if i < 0 {
			writeJSON(w, http.StatusNotFound, errBody("not_found", "Domain not found"))
			return
		}
		s.domains = slices.Delete(s.domains, i, i+1)
		w.WriteHeader(http.StatusNoContent)
	case route == "GET clients" && len(seg) == 1:
		writeJSON(w, http.StatusOK, map[string]any{"clients": s.clients})
	case r.Method == http.MethodPut && seg[0] == "clients" && len(seg) == 2:
		s.putClient(w, r, seg[1])
	case route == "POST clients" && len(seg) == 1:
		s.postClient(w, r)
	case r.Method == http.MethodDelete && seg[0] == "clients" && len(seg) == 2:
		i := slices.IndexFunc(s.clients, func(c Client) bool { return c.Client == seg[1] })
		if i < 0 {
			writeJSON(w, http.StatusNotFound, errBody("not_found", "Client not found"))
			return
		}
		s.clients = slices.Delete(s.clients, i, i+1)
		w.WriteHeader(http.StatusNoContent)
	case route == "GET groups" && len(seg) == 1:
		writeJSON(w, http.StatusOK, map[string]any{"groups": s.groups})
	case route == "POST groups" && len(seg) == 1:
		s.putGroup(w, r, "", true)
	case r.Method == http.MethodPut && seg[0] == "groups" && len(seg) == 2:
		s.putGroup(w, r, seg[1], false)
	case r.Method == http.MethodDelete && seg[0] == "groups" && len(seg) == 2:
		s.deleteGroup(w, seg[1])
	case route == "GET lists" && len(seg) == 1:
		writeJSON(w, http.StatusOK, map[string]any{"lists": s.lists})
	case route == "GET queries" && len(seg) == 1:
		s.listQueries(w, r)
	default:
		writeJSON(w, http.StatusNotFound, errBody("not_found", "Not found"))
	}
}

// blockingJSON is called with s.mu held.
func (s *Server) blockingJSON() map[string]any {
	state := "disabled"
	if s.blocking {
		state = "enabled"
	}
	return map[string]any{"blocking": state, "timer": s.timer}
}

func validList(listType, kind string) bool {
	return (listType == "allow" || listType == "deny") && (kind == "exact" || kind == "regex")
}

// findDomain is called with s.mu held.
func (s *Server) findDomain(domain, listType, kind string) int {
	return slices.IndexFunc(s.domains, func(d Domain) bool {
		return d.Domain == domain && d.Type == listType && d.Kind == kind
	})
}

type domainBody struct {
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Kind    string `json:"kind"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	Enabled *bool  `json:"enabled"`
}

// postDomain is called with s.mu held. An exact domain with a space in it stands in for anything Pi-hole's own
// validation refuses.
func (s *Server) postDomain(w http.ResponseWriter, r *http.Request, listType, kind string) {
	var in domainBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !validList(listType, kind) {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request"))
		return
	}
	if in.Domain == "" || (kind == "exact" && strings.ContainsAny(in.Domain, " \t")) {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid domain"))
		return
	}
	if s.findDomain(in.Domain, listType, kind) >= 0 {
		writeJSON(w, http.StatusCreated, map[string]any{
			"domains": []Domain{},
			"processed": map[string]any{
				"success": []any{},
				"errors":  []any{map[string]string{"item": in.Domain, "error": "UNIQUE constraint failed: domainlist.domain, domainlist.type"}},
			},
		})
		return
	}
	d := Domain{
		ID: s.id(), Domain: in.Domain, Type: listType, Kind: kind, Comment: in.Comment, Groups: in.Groups,
		Enabled: in.Enabled == nil || *in.Enabled, DateAdded: s.now, DateModified: s.now,
	}
	if d.Groups == nil {
		d.Groups = []int{0}
	}
	s.domains = append(s.domains, d)
	writeJSON(w, http.StatusCreated, map[string]any{
		"domains":   []Domain{d},
		"processed": map[string]any{"success": []any{map[string]string{"item": d.Domain}}, "errors": []any{}},
	})
}

// putDomain is called with s.mu held. Like Pi-hole, it creates the entry if it doesn't exist, and enables it unless
// the body says otherwise.
func (s *Server) putDomain(w http.ResponseWriter, r *http.Request, listType, kind, domain string) {
	var in domainBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !validList(listType, kind) {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request"))
		return
	}
	enabled := in.Enabled == nil || *in.Enabled
	groups := in.Groups
	if groups == nil {
		groups = []int{0}
	}
	i := s.findDomain(domain, listType, kind)
	if i < 0 {
		s.domains = append(s.domains, Domain{
			ID: s.id(), Domain: domain, Type: listType, Kind: kind, DateAdded: s.now,
		})
		i = len(s.domains) - 1
	}
	d := &s.domains[i]
	d.Comment, d.Groups, d.Enabled, d.DateModified = in.Comment, groups, enabled, s.now+1
	writeJSON(w, http.StatusOK, map[string]any{
		"domains":   []Domain{*d},
		"processed": map[string]any{"success": []any{map[string]string{"item": domain}}, "errors": []any{}},
	})
}

// putClient is called with s.mu held. Like Pi-hole, it creates the client if it doesn't exist.
func (s *Server) putClient(w http.ResponseWriter, r *http.Request, client string) {
	var in struct {
		Comment string `json:"comment"`
		Groups  []int  `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request"))
		return
	}
	groups := in.Groups
	if groups == nil {
		groups = []int{0}
	}
	i := slices.IndexFunc(s.clients, func(c Client) bool { return c.Client == client })
	if i < 0 {
		s.clients = append(s.clients, Client{ID: s.id(), Client: client, DateAdded: s.now})
		i = len(s.clients) - 1
	}
	c := &s.clients[i]
	c.Comment, c.Groups, c.DateModified = in.Comment, groups, s.now+1
	writeJSON(w, http.StatusOK, map[string]any{
		"clients":   []Client{*c},
		"processed": map[string]any{"success": []any{map[string]string{"item": client}}, "errors": []any{}},
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Password != s.password {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"session": map[string]any{"valid": false, "sid": nil, "validity": -1},
			"error":   map[string]string{"key": "unauthorized"},
		})
		return
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	sid := base64.RawURLEncoding.EncodeToString(b)
	s.sessions[sid] = true
	s.logins++
	writeJSON(w, http.StatusOK, map[string]any{
		"session": map[string]any{"valid": true, "sid": sid, "validity": s.validity},
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-FTL-SID")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessions[sid] {
		writeJSON(w, http.StatusUnauthorized, errBody("unauthorized", "Unauthorized"))
		return
	}
	delete(s.sessions, sid)
	s.logouts++
	w.WriteHeader(http.StatusNoContent)
}

func errBody(key, message string) map[string]any {
	return map[string]any{"error": map[string]any{"key": key, "message": message, "hint": nil}}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// postClient is called with s.mu held. A client that already exists is listed under processed.errors, as Pi-hole does.
func (s *Server) postClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Client  string `json:"client"`
		Comment string `json:"comment"`
		Groups  []int  `json:"groups"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Client == "" {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request"))
		return
	}
	if slices.ContainsFunc(s.clients, func(c Client) bool { return c.Client == in.Client }) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"clients": []Client{},
			"processed": map[string]any{"success": []any{},
				"errors": []any{map[string]string{"item": in.Client, "error": "UNIQUE constraint failed: client.ip"}}},
		})
		return
	}
	groups := in.Groups
	if groups == nil {
		groups = []int{0}
	}
	c := Client{ID: s.id(), Client: in.Client, Comment: in.Comment, Groups: groups, DateAdded: s.now, DateModified: s.now}
	s.clients = append(s.clients, c)
	writeJSON(w, http.StatusCreated, map[string]any{
		"clients":   []Client{c},
		"processed": map[string]any{"success": []any{map[string]string{"item": c.Client}}, "errors": []any{}},
	})
}

// putGroup is called with s.mu held. It answers as FTL's group writes do. POST (create) refuses a name already
// taken. PUT with no name in the body, or the same one, updates the group called name, creating it if it doesn't
// exist. PUT with a different name renames, as FTL's UPDATE ... WHERE name = :item does: a group that doesn't exist
// changes nothing and still answers 200, and a new name already taken fails the UNIQUE constraint with a 400. A
// body without enabled sets it to true, and one without a comment clears it. Newlines are refused in any name.
func (s *Server) putGroup(w http.ResponseWriter, r *http.Request, name string, create bool) {
	var in struct {
		Name    string `json:"name"`
		Comment string `json:"comment"`
		Enabled *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || (create && in.Name == "") {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Invalid request: No valid \"name\" in payload"))
		return
	}
	if create {
		name = in.Name
	}
	newName := name
	if in.Name != "" {
		newName = in.Name
	}
	if strings.ContainsAny(name+newName, "\r\n") {
		writeJSON(w, http.StatusBadRequest, errBody("bad_request", "Newlines and carriage returns are not allowed in any input"))
		return
	}
	enabled := in.Enabled == nil || *in.Enabled
	i := s.groupIndex(name)
	switch {
	case create && i >= 0:
		writeJSON(w, http.StatusCreated, map[string]any{
			"groups": []Group{},
			"processed": map[string]any{"success": []any{},
				"errors": []any{map[string]string{"item": in.Name, "error": "UNIQUE constraint failed: group.name"}}},
		})
		return
	case newName != name:
		if i >= 0 && s.groupIndex(newName) >= 0 {
			writeJSON(w, http.StatusBadRequest, errBody("database_error", "Could not add to gravity database"))
			return
		}
		if i >= 0 {
			s.groups[i].Name, s.groups[i].Comment, s.groups[i].Enabled = newName, in.Comment, enabled
		}
	default:
		if i < 0 {
			s.groups = append(s.groups, Group{ID: s.id(), Name: name})
			i = len(s.groups) - 1
		}
		s.groups[i].Comment, s.groups[i].Enabled = in.Comment, enabled
	}
	status, reply := http.StatusOK, []Group{}
	if create {
		status = http.StatusCreated
	}
	if j := s.groupIndex(newName); j >= 0 {
		reply = append(reply, s.groups[j])
	}
	writeJSON(w, status, map[string]any{
		"groups":    reply,
		"processed": map[string]any{"success": []any{map[string]string{"item": name}}, "errors": []any{}},
	})
}

// deleteGroup is called with s.mu held. As in Pi-hole's database, deleting a group takes it off every domain, client
// and list, and deleting the Default group (ID 0) is allowed: a trigger then recreates it, empty, with no comment.
// A name that doesn't exist is a 404 with an empty body.
func (s *Server) deleteGroup(w http.ResponseWriter, name string) {
	i := s.groupIndex(name)
	if i < 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{})
		return
	}
	id := s.groups[i].ID
	s.groups = slices.Delete(s.groups, i, i+1)
	drop := func(ids []int) []int { return slices.DeleteFunc(ids, func(g int) bool { return g == id }) }
	for j := range s.domains {
		s.domains[j].Groups = drop(s.domains[j].Groups)
	}
	for j := range s.clients {
		s.clients[j].Groups = drop(s.clients[j].Groups)
	}
	for j := range s.lists {
		s.lists[j].Groups = drop(s.lists[j].Groups)
	}
	if id == 0 {
		s.groups = slices.Insert(s.groups, 0, Group{ID: 0, Name: "Default", Enabled: true})
	}
	w.WriteHeader(http.StatusNoContent)
}

// groupIndex is called with s.mu held. Names are compared exactly, as in Pi-hole's database.
func (s *Server) groupIndex(name string) int {
	return slices.IndexFunc(s.groups, func(g Group) bool { return g.Name == name })
}

// Groups returns the Pi-hole groups.
func (s *Server) Groups() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.groups)
}
