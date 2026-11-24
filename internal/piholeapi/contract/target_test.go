// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package contract_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// The environment of a run against a real Pi-hole. Only the first is needed to choose it.
const (
	// envURL is the Pi-hole's base URL, such as http://127.0.0.1:8081. Unset, the tests run against the fake.
	envURL = "PIHOLE_RBAC_TEST_PIHOLE"
	// envPassword is its web interface password. The tests use it to create their own app password and turn
	// webserver.api.app_sudo on, as an admin setting up the app would, and to turn app_sudo off and on again, which
	// the app password itself can't do.
	envPassword = "PIHOLE_RBAC_TEST_PIHOLE_PASSWORD"
	// envDNS is the address of its DNS server, host:port, which the query log tests send queries to. The default
	// is the URL's host on port 53.
	envDNS = "PIHOLE_RBAC_TEST_PIHOLE_DNS"
)

// lockedDHCPItem is the one config item the Pi-hole under test must have set through an environment variable
// (FTLCONF_dhcp_leaseTime), so the tests can check how FTL refuses to change it. Nothing else may be set that way
// for the items the tests write. The fake marks the same item locked.
const lockedDHCPItem = "leaseTime"

// prefix starts the name of everything the tests create, so a run can tell its own leftovers from anything else.
const prefix = "contract-"

// fakePassword is the fake's app password.
const fakePassword = "contract-app-password"

// live is the real Pi-hole, set up by TestMain, or nil to use the fake.
var live *realPihole

func TestMain(m *testing.M) {
	if u := os.Getenv(envURL); u != "" {
		r, err := setUpReal(u, os.Getenv(envPassword), os.Getenv(envDNS))
		if err != nil {
			fmt.Fprintln(os.Stderr, "contract tests against", u+":", err)
			os.Exit(1)
		}
		live = r
	}
	os.Exit(m.Run())
}

// target is the Pi-hole one test runs against.
type target struct {
	url      string
	password string
	fake     *piholetest.Server // nil for a real Pi-hole
	queries  []piholetest.Query // the fake's query log, newest first
	nextID   int
}

// newTarget returns the Pi-hole for t: a new fake, set up as the real one is, or the real Pi-hole.
func newTarget(t *testing.T) *target {
	t.Helper()
	if live != nil {
		return &target{url: live.url, password: live.appPassword}
	}
	f := piholetest.New(t, fakePassword)
	f.SetAppSudo(true)
	f.LockDHCP(lockedDHCPItem)
	// As a real Pi-hole (FTL v6.9) was seen restarting: refusing a connection, answering one, then refusing again.
	f.SetRestartPattern(1, 1, 3)
	t.Cleanup(piholeapi.SetRestartTiming(5*time.Millisecond, 50*time.Millisecond))
	return &target{url: f.URL, password: fakePassword, fake: f}
}

// real says whether the target is a real Pi-hole.
func (tg *target) real() bool { return tg.fake == nil }

// client returns a client with the app password, closed (logging out) when the test ends. FTL limits how many
// sessions it keeps, so every client is closed.
func (tg *target) client(t *testing.T) *piholeapi.Client {
	t.Helper()
	return tg.clientWith(t, tg.password)
}

func (tg *target) clientWith(t *testing.T, password string) *piholeapi.Client {
	t.Helper()
	c, err := piholeapi.New(piholeapi.Options{BaseURL: tg.url, Password: secrets.NewValue([]byte(password))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// setAppSudo turns webserver.api.app_sudo on or off. Turned off, it is turned on again when the test ends.
func (tg *target) setAppSudo(t *testing.T, on bool) {
	t.Helper()
	if !on {
		t.Cleanup(func() { tg.setAppSudo(t, true) })
	}
	if tg.real() {
		live.setAppSudo(t, on)
		return
	}
	tg.fake.SetAppSudo(on)
}

// query puts a type A query for domain from 127.0.0.1 in the query log. A real Pi-hole is sent the query, and the
// test waits until its log shows it; the fake has it added with status, which is what FTL logs for it.
func (tg *target) query(t *testing.T, c *piholeapi.Client, domain, status string) {
	t.Helper()
	if !tg.real() {
		q := piholetest.Query{ID: tg.nextID, Time: float64(time.Now().UnixMicro()) / 1e6, Type: "A", Domain: domain, Status: status}
		q.Client.IP = "127.0.0.1"
		tg.nextID++
		tg.queries = append([]piholetest.Query{q}, tg.queries...)
		tg.fake.SetQueries(tg.queries)
		return
	}
	ctx := context.Background()
	before, err := c.QueryLog(ctx, piholeapi.QueryFilter{Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	live.lookup(t, domain)
	for deadline := time.Now().Add(5 * time.Second); ; {
		page, err := c.QueryLog(ctx, piholeapi.QueryFilter{Domain: domain})
		if err != nil {
			t.Fatal(err)
		}
		if page.Filtered > before.Filtered {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the query for %s didn't reach the query log", domain)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// deny puts domain on the deny list (exact), deleted when the test ends, and waits until Pi-hole blocks it. FTL
// reloads its lists after a change in the background, so a query sent at once can still be forwarded. A real
// Pi-hole is asked for a second denied domain until it answers 0.0.0.0, which leaves domain's own log untouched.
func (tg *target) deny(t *testing.T, c *piholeapi.Client, domain string) {
	t.Helper()
	ctx := context.Background()
	probe := name(".example")
	for _, d := range []string{domain, probe} {
		if _, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact", Groups: []int{0}}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.DeleteDomain(ctx, d, "deny", "exact") })
	}
	if !tg.real() {
		return
	}
	for deadline := time.Now().Add(10 * time.Second); live.lookup(t, probe) != netip.IPv4Unspecified(); {
		if time.Now().After(deadline) {
			t.Fatal("Pi-hole didn't start blocking a denied domain")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// name returns a new name for something a test creates: prefix, eight random hex digits, then suffix.
func name(suffix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b) + suffix
}

// realPihole is the Pi-hole a real run uses.
type realPihole struct {
	url, webPassword, appPassword, dns string
	admin                              *http.Client
	firstQueries                       *piholeapi.QueryPage // the query log as it was before any test ran
}

// firstQueryPage is the query log as it was before any test ran, or nil without a real Pi-hole.
func (r *realPihole) firstQueryPage() *piholeapi.QueryPage {
	if r == nil {
		return nil
	}
	return r.firstQueries
}

// setUpReal checks the Pi-hole is a throwaway one, before changing anything. Then it does what an admin does before
// adding a Pi-hole to the app: creates an app password and turns app_sudo on, both through the API with the web
// interface password. Last, it deletes what an earlier, interrupted run left behind.
func setUpReal(rawURL, webPassword, dns string) (*realPihole, error) {
	base, err := piholeapi.ParseBaseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if webPassword == "" {
		return nil, errors.New(envPassword + " (the web interface password) isn't set")
	}
	if dns == "" {
		host := strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		dns = net.JoinHostPort(strings.Trim(host, "[]"), "53")
	}
	r := &realPihole{url: base, webPassword: webPassword, dns: dns, admin: &http.Client{Timeout: 30 * time.Second}}
	if err := r.checkThrowaway(); err != nil {
		return nil, err
	}
	var app struct {
		App struct {
			Password string `json:"password"`
			Hash     string `json:"hash"`
		} `json:"app"`
	}
	if err := r.adminDo(http.MethodGet, "/api/auth/app", nil, &app); err != nil {
		return nil, fmt.Errorf("creating an app password: %w", err)
	}
	if app.App.Password == "" || app.App.Hash == "" {
		return nil, errors.New("creating an app password: no password in the answer")
	}
	set := map[string]any{"config": map[string]any{"webserver": map[string]any{"api": map[string]any{
		"app_pwhash": app.App.Hash, "app_sudo": true,
	}}}}
	if err := r.adminDo(http.MethodPatch, "/api/config", set, nil); err != nil {
		return nil, fmt.Errorf("setting the app password: %w", err)
	}
	r.appPassword = app.App.Password
	if err := r.clearLeftovers(); err != nil {
		return nil, err
	}
	return r, nil
}

// adminDo makes one request with a web-password session of its own, which it ends afterwards. A config change can
// end every session, so none is kept between requests.
func (r *realPihole) adminDo(method, path string, body, out any) error {
	sid, err := r.adminLogin()
	if err != nil {
		return err
	}
	defer func() {
		req, _ := http.NewRequest(http.MethodDelete, r.url+"/api/auth", nil)
		req.Header.Set("X-FTL-SID", sid)
		if resp, err := r.admin.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.url+path, payload)
	if err != nil {
		return err
	}
	req.Header.Set("X-FTL-SID", sid)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.admin.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (r *realPihole) adminLogin() (string, error) {
	b, _ := json.Marshal(map[string]string{"password": r.webPassword})
	resp, err := r.admin.Post(r.url+"/api/auth", "application/json", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Session struct {
			Valid bool    `json:"valid"`
			SID   *string `json:"sid"`
		} `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("logging in with the web interface password: %w", err)
	}
	if !out.Session.Valid || out.Session.SID == nil {
		return "", fmt.Errorf("logging in with the web interface password: refused (%s)", resp.Status)
	}
	return *out.Session.SID, nil
}

// setAppSudo sets webserver.api.app_sudo with the web interface password.
func (r *realPihole) setAppSudo(t *testing.T, on bool) {
	t.Helper()
	set := map[string]any{"config": map[string]any{"webserver": map[string]any{"api": map[string]any{"app_sudo": on}}}}
	if err := r.adminDo(http.MethodPatch, "/api/config", set, nil); err != nil {
		t.Fatalf("setting app_sudo: %v", err)
	}
}

// checkThrowaway refuses a Pi-hole holding domains, clients, Pi-hole groups or lists that aren't the tests' own, before
// anything on it is changed. The Default group is allowed, as is the list Pi-hole's Docker image subscribes a fresh
// volume to: nobody minds losing either on a throwaway Pi-hole. It reads with the web interface password.
func (r *realPihole) checkThrowaway() error {
	var domains struct {
		Domains []piholeapi.DomainEntry `json:"domains"`
	}
	var clients struct {
		Clients []piholeapi.ClientEntry `json:"clients"`
	}
	var groups struct {
		Groups []piholeapi.Group `json:"groups"`
	}
	var lists struct {
		Lists []piholeapi.ListEntry `json:"lists"`
	}
	for path, out := range map[string]any{"/api/domains": &domains, "/api/clients": &clients, "/api/groups": &groups, "/api/lists": &lists} {
		if err := r.adminDo(http.MethodGet, path, nil, out); err != nil {
			return err
		}
	}
	var foreign []string
	for _, d := range domains.Domains {
		if !strings.HasPrefix(d.Domain, prefix) {
			foreign = append(foreign, "domain "+d.Domain)
		}
	}
	for _, c := range clients.Clients {
		// Clients are addresses; the tests' own have a comment starting with the prefix.
		if !strings.HasPrefix(c.Comment, prefix) {
			foreign = append(foreign, "client "+c.Client)
		}
	}
	for _, g := range groups.Groups {
		if g.ID != 0 && !strings.HasPrefix(g.Name, prefix) {
			foreign = append(foreign, "group "+g.Name)
		}
	}
	for _, l := range lists.Lists {
		if !strings.Contains(l.Address, prefix) && l.Address != dockerDefaultList {
			foreign = append(foreign, "list "+l.Address)
		}
	}
	if len(foreign) > 0 {
		return fmt.Errorf("refusing a Pi-hole that isn't a throwaway one: it has %s", strings.Join(foreign, ", "))
	}
	return nil
}

// clearLeftovers reads the query log as it is before any test, for TestQueryLogEmpty, then deletes what an
// interrupted run left behind.
func (r *realPihole) clearLeftovers() error {
	c, err := piholeapi.New(piholeapi.Options{BaseURL: r.url, Password: secrets.NewValue([]byte(r.appPassword))})
	if err != nil {
		return err
	}
	ctx := context.Background()
	defer func() { _ = c.Close(ctx) }()
	if r.firstQueries, err = c.QueryLog(ctx, piholeapi.QueryFilter{}); err != nil {
		return err
	}
	domains, err := c.ListDomains(ctx)
	if err != nil {
		return err
	}
	for _, d := range domains {
		if err := c.DeleteDomain(ctx, d.Domain, d.Type, d.Kind); err != nil {
			return err
		}
	}
	clients, err := c.ListClients(ctx)
	if err != nil {
		return err
	}
	for _, cl := range clients {
		if err := c.DeleteClient(ctx, cl.Client); err != nil {
			return err
		}
	}
	groups, err := c.ListGroups(ctx)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if g.ID != 0 {
			if err := c.DeleteGroup(ctx, g.Name); err != nil {
				return err
			}
		}
	}
	lists, err := c.ListLists(ctx)
	if err != nil {
		return err
	}
	for _, l := range lists {
		if l.Address != dockerDefaultList {
			if err := c.DeleteList(ctx, l.Address, l.Type); err != nil {
				return err
			}
		}
	}
	return nil
}

// dockerDefaultList is the list Pi-hole's Docker image subscribes a fresh volume to.
const dockerDefaultList = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

// lookup sends one type A query for domain to the Pi-hole's DNS server, as a single datagram with no retries and no
// search domains, so the query log gets exactly one entry for it. It returns the first address in the answer, if any.
func (r *realPihole) lookup(t *testing.T, domain string) netip.Addr {
	t.Helper()
	conn, err := net.Dial("udp", r.dns)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	id := uint16(time.Now().UnixNano())
	msg := binary.BigEndian.AppendUint16(nil, id)
	msg = append(msg, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // recursion desired; one question
	for _, label := range strings.Split(domain, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1) // root; type A; class IN
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 || binary.BigEndian.Uint16(buf) != id {
		return netip.Addr{} // no answer worth reading; the query still reached the log
	}
	return firstA(buf[:n], len(msg))
}

// firstA returns the address in the first A record of the answer section of a DNS reply whose question section ends
// at off, or the zero Addr.
func firstA(b []byte, off int) netip.Addr {
	if binary.BigEndian.Uint16(b[6:]) == 0 {
		return netip.Addr{}
	}
	// The answer's name: a pointer (two bytes) or labels.
	for off < len(b) {
		if b[off]&0xc0 == 0xc0 {
			off += 2
			break
		}
		if b[off] == 0 {
			off++
			break
		}
		off += int(b[off]) + 1
	}
	if off+10 > len(b) {
		return netip.Addr{}
	}
	typ, rdlen := binary.BigEndian.Uint16(b[off:]), int(binary.BigEndian.Uint16(b[off+8:]))
	off += 10
	if typ != 1 || rdlen != 4 || off+4 > len(b) {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(b[off : off+4]))
}
