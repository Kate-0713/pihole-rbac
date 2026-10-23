// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package piholeapi is a client for the Pi-hole v6 REST API. A Client logs in to one Pi-hole with its app password,
// reuses the session until shortly before it expires, and logs in again if Pi-hole forgets the session early (after
// a restart, say). Which calls a user may make is decided before a request reaches this package.
package piholeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// TLSMode says how a Pi-hole's HTTPS certificate is checked. The values match instances.tls_mode.
type TLSMode string

const (
	// TLSVerify checks the certificate against the system's trusted CAs, plus the CA file if one is given.
	TLSVerify TLSMode = "verify"
	// TLSInsecure skips certificate checks. For labs only.
	TLSInsecure TLSMode = "insecure"
)

// DefaultTimeout bounds each request to Pi-hole, including the login it may need first.
const DefaultTimeout = 10 * time.Second

const (
	maxResponseBytes = 16 << 20 // the query log is the largest response, at up to 1000 entries
	maxAuthBytes     = 64 << 10
	refreshMargin    = 30 * time.Second // log in again this long before Pi-hole's session expires
	maxQueryLog      = 1000
)

// Options configures a Client.
type Options struct {
	BaseURL  string // checked with ParseBaseURL
	Password secrets.Value
	TLSMode  TLSMode // TLSVerify if empty
	CAFile   string  // extra trusted CAs (PEM), only with TLSVerify
	Timeout  time.Duration
}

// Client talks to one Pi-hole. It is safe for concurrent use.
type Client struct {
	baseURL   string
	password  secrets.Value
	http      *http.Client
	transport *http.Transport
	now       func() time.Time

	mu      sync.Mutex // held while logging in, so concurrent requests share one login
	sid     string
	expires time.Time
	closed  bool
}

// New checks the options and builds a client. It doesn't contact Pi-hole.
func New(opts Options) (*Client, error) {
	base, err := ParseBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.Password.IsZero() {
		return nil, errors.New("piholeapi: the app password is empty")
	}
	tlsCfg, err := tlsConfig(opts.TLSMode, opts.CAFile)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := &http.Transport{
		// Pi-holes are on the local network. A proxy set in the environment for outbound traffic (the update check)
		// mustn't capture them.
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &Client{
		baseURL:  base,
		password: opts.Password,
		http: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// A redirect would send the session ID, and on login the password, somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		transport: transport,
		now:       time.Now,
	}, nil
}

// ParseBaseURL checks a Pi-hole base URL and returns it in canonical form, without a trailing slash. It must be http
// or https with a host, and have no username, password, query or fragment. A path is allowed, for a Pi-hole behind a
// reverse proxy under a prefix, but not one ending in /admin or /api: the API lives at <base>/api.
func ParseBaseURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Opaque != "" {
		return "", errors.New("base URL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("base URL must start with http:// or https://")
	}
	if u.Hostname() == "" {
		return "", errors.New("base URL has no host")
	}
	if u.User != nil {
		return "", errors.New("base URL must not contain a username or password")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("base URL must not have a query or fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", errors.New("base URL has an invalid port")
		}
	}
	path := strings.TrimRight(u.Path, "/")
	if lower := strings.ToLower(path); strings.HasSuffix(lower, "/admin") || strings.HasSuffix(lower, "/api") {
		return "", errors.New("base URL should be the Pi-hole's address without /admin or /api")
	}
	u.Path, u.RawPath = path, ""
	return u.String(), nil
}

func tlsConfig(mode TLSMode, caFile string) (*tls.Config, error) {
	switch mode {
	case TLSVerify, "":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if caFile == "" {
			return cfg, nil
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if err := addCAFile(pool, caFile); err != nil {
			return nil, fmt.Errorf("piholeapi: %w", err)
		}
		cfg.RootCAs = pool
		return cfg, nil
	case TLSInsecure:
		if caFile != "" {
			return nil, errors.New("piholeapi: a CA file can only be used with TLS mode verify")
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, nil
	default:
		return nil, fmt.Errorf("piholeapi: unknown TLS mode %q", mode)
	}
}

// CheckCAFile reports whether path can be read and holds at least one PEM certificate, so instance settings can be
// checked when they are saved rather than when the client is built.
func CheckCAFile(path string) error {
	return addCAFile(x509.NewCertPool(), path)
}

func addCAFile(pool *x509.CertPool, path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("CA file: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("CA file %s holds no PEM certificates", path)
	}
	return nil
}

// BaseURL returns the canonical base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// Close logs out of Pi-hole, so the session doesn't hold one of Pi-hole's limited API seats until it expires, and
// closes idle connections. Later calls fail with ErrClosed. A failed logout is returned but leaves the client closed.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	sid := c.sid
	c.sid, c.expires, c.closed = "", time.Time{}, true
	c.mu.Unlock()
	defer c.transport.CloseIdleConnections()
	if sid == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/api/auth", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-FTL-SID", sid)
	resp, err := c.http.Do(req)
	if err != nil {
		return c.transportError(ctx, "logging out of", err)
	}
	drain(resp)
	// 401 means Pi-hole had already forgotten the session.
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusUnauthorized {
		return &StatusError{Code: resp.StatusCode, Method: http.MethodDelete, Path: "/api/auth"}
	}
	return nil
}

type authResponse struct {
	Session struct {
		Valid    bool   `json:"valid"`
		SID      string `json:"sid"`
		Validity int    `json:"validity"` // seconds
	} `json:"session"`
}

// session returns a valid session ID, logging in if there isn't one or it is about to expire.
func (c *Client) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return "", ErrClosed
	}
	if c.sid != "" && c.now().Before(c.expires) {
		return c.sid, nil
	}
	return c.login(ctx)
}

// login is called with c.mu held.
func (c *Client) login(ctx context.Context) (string, error) {
	body, err := json.Marshal(struct {
		Password string `json:"password"`
	}{c.password.Reveal()})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/auth", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", c.transportError(ctx, "logging in to", err)
	}
	defer drain(resp)

	var out authResponse
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxAuthBytes)).Decode(&out)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", ErrAuthRejected
	case resp.StatusCode/100 != 2:
		return "", &StatusError{Code: resp.StatusCode, Method: http.MethodPost, Path: "/api/auth"}
	case decodeErr != nil:
		return "", &badResponseError{what: "login response", err: decodeErr}
	case !out.Session.Valid:
		return "", ErrAuthRejected
	case out.Session.SID == "":
		return "", &badResponseError{what: "login response", err: errors.New("no session ID")}
	}

	validity := time.Duration(out.Session.Validity) * time.Second
	ttl := validity - refreshMargin
	if validity < 2*refreshMargin {
		ttl = validity / 2
	}
	c.sid, c.expires = out.Session.SID, c.now().Add(ttl)
	return c.sid, nil
}

// forget drops sid if it is still the cached session, so the next call logs in again.
func (c *Client) forget(sid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sid == sid {
		c.sid, c.expires = "", time.Time{}
	}
}

// do makes an authenticated request and decodes a JSON response into out (nil to ignore the body). If Pi-hole
// answers 401 to a cached session, the session is dropped and the request is tried once more with a new login: a
// 401 means Pi-hole refused it before acting on it, so the retry is safe for writes too.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		sid, err := c.session(ctx)
		if err != nil {
			return err
		}
		code, err := c.send(ctx, method, path, sid, payload, out)
		if code == http.StatusUnauthorized && attempt == 0 {
			c.forget(sid)
			continue
		}
		return err
	}
}

func (c *Client) send(ctx context.Context, method, path, sid string, payload []byte, out any) (int, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-FTL-SID", sid)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, c.transportError(ctx, "calling", err)
	}
	defer drain(resp)
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, statusError(resp, method, path)
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out)
	if _, isWrite := out.(*writeResponse); isWrite && errors.Is(err, io.EOF) {
		return resp.StatusCode, nil // a write answered with an empty body: nothing to check
	}
	if err != nil {
		return resp.StatusCode, &badResponseError{what: "response to " + method + " " + path, err: err}
	}
	return resp.StatusCode, nil
}

// piholeError is the body Pi-hole sends with an error status.
type piholeError struct {
	Error struct {
		Key     string `json:"key"`
		Message string `json:"message"`
		Hint    any    `json:"hint"` // a string, or null
	} `json:"error"`
}

// statusError builds the error for a non-2xx answer, with Pi-hole's message if the body has one. A 400 means Pi-hole
// refused the request's content, which is a RejectedError rather than a sign of trouble with Pi-hole.
func statusError(resp *http.Response, method, path string) error {
	var body piholeError
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxAuthBytes)).Decode(&body)
	msg := body.Error.Message
	if hint, ok := body.Error.Hint.(string); ok && hint != "" {
		msg += " (" + hint + ")"
	}
	msg = cleanMessage(msg)
	if resp.StatusCode == http.StatusBadRequest {
		return &RejectedError{Method: method, Path: path, Message: msg}
	}
	return &StatusError{Code: resp.StatusCode, Method: method, Path: path, Message: msg}
}

// writeResponse is the part of a write's response this client reads. Pi-hole reports items it couldn't add or
// change under processed.errors, with a 2xx status, and returns the entries as saved under domains or clients.
type writeResponse struct {
	Domains   []DomainEntry `json:"domains"`
	Clients   []ClientEntry `json:"clients"`
	Processed *struct {
		Errors []struct {
			Item  any    `json:"item"` // usually a string; a number for some endpoints
			Error string `json:"error"`
		} `json:"errors"`
	} `json:"processed"`
}

// write makes a state-changing call and turns an item Pi-hole lists under processed.errors into a RejectedError.
func (c *Client) write(ctx context.Context, method, path string, body any, out *writeResponse) error {
	if out == nil {
		out = new(writeResponse)
	}
	if err := c.do(ctx, method, path, body, out); err != nil {
		return err
	}
	if out.Processed == nil || len(out.Processed.Errors) == 0 {
		return nil
	}
	first := out.Processed.Errors[0]
	item := ""
	if first.Item != nil {
		item = cleanMessage(fmt.Sprint(first.Item))
	}
	return &RejectedError{Method: method, Path: path, Item: item, Message: cleanMessage(first.Error)}
}

// transportError reports a cancelled or expired caller context as itself, so a user closing the page isn't
// mistaken for Pi-hole being down. Anything else is ErrUnreachable.
func (c *Client) transportError(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return &unreachableError{op: op, err: err}
}

// drain reads a little of what's left of the body so the connection can be reused, then closes it.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// --- API calls ---

// Blocking states Pi-hole reports. Failed and unknown mean FTL couldn't tell.
const (
	BlockingEnabled  = "enabled"
	BlockingDisabled = "disabled"
)

// Status is the response of /api/dns/blocking.
type Status struct {
	Blocking string `json:"blocking"` // "enabled", "disabled", "failed" or "unknown"
	// Timer is how many seconds remain until blocking flips back, or nil when no timer is running.
	Timer *float64 `json:"timer"`
}

// GetStatus returns the blocking status. It is also the health check: cheap, and it needs a valid login.
func (c *Client) GetStatus(ctx context.Context) (*Status, error) {
	var out Status
	if err := c.do(ctx, http.MethodGet, "/api/dns/blocking", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MaxBlockingTimer is the longest timer SetBlocking accepts.
const MaxBlockingTimer = 24 * time.Hour

// SetBlocking turns blocking on or off and returns the new status. With a timer above zero, Pi-hole flips blocking
// back once it runs out; it is sent in whole seconds, rounded up, and can't exceed MaxBlockingTimer.
func (c *Client) SetBlocking(ctx context.Context, enabled bool, timer time.Duration) (*Status, error) {
	if timer < 0 || timer > MaxBlockingTimer {
		return nil, fmt.Errorf("%w: blocking timer %s", ErrInvalidArgument, timer)
	}
	body := struct {
		Blocking bool   `json:"blocking"`
		Timer    *int64 `json:"timer"` // null: no timer
	}{Blocking: enabled}
	if timer > 0 {
		secs := int64((timer + time.Second - 1) / time.Second)
		body.Timer = &secs
	}
	var out Status
	if err := c.do(ctx, http.MethodPost, "/api/dns/blocking", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RestartDNS restarts Pi-hole's DNS resolver. FTL's API goes down with it, so the request can fail with
// ErrUnreachable even when the restart happened.
func (c *Client) RestartDNS(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/action/restartdns", nil, nil)
}

// DomainEntry is one entry on Pi-hole's allow or deny list. Domain, Type and Kind identify it: the same domain can be
// on both lists, or be both an exact and a regex entry. ID is Pi-hole's row ID, which differs between Pi-holes.
type DomainEntry struct {
	ID           int    `json:"id"`
	Domain       string `json:"domain"`
	Type         string `json:"type"` // "allow" or "deny"
	Kind         string `json:"kind"` // "exact" or "regex"
	Comment      string `json:"comment"`
	Groups       []int  `json:"groups"`
	Enabled      bool   `json:"enabled"`
	DateAdded    int64  `json:"date_added"`    // Unix seconds
	DateModified int64  `json:"date_modified"` // Unix seconds
}

// ValidDomainType reports whether t is a domain list type Pi-hole accepts in a path.
func ValidDomainType(t string) bool { return t == "allow" || t == "deny" }

// ValidDomainKind reports whether k is a domain kind Pi-hole accepts in a path.
func ValidDomainKind(k string) bool { return k == "exact" || k == "regex" }

func checkDomainPath(listType, kind string) error {
	if !ValidDomainType(listType) {
		return fmt.Errorf("%w: domain type %q", ErrInvalidArgument, listType)
	}
	if !ValidDomainKind(kind) {
		return fmt.Errorf("%w: domain kind %q", ErrInvalidArgument, kind)
	}
	return nil
}

func domainPath(listType, kind, domain string) string {
	return "/api/domains/" + listType + "/" + kind + "/" + url.PathEscape(domain)
}

func nonNil(ids []int) []int {
	if ids == nil {
		return []int{} // [] rather than null: no groups
	}
	return ids
}

// ListDomains returns every allow and deny list entry.
func (c *Client) ListDomains(ctx context.Context) ([]DomainEntry, error) {
	var out struct {
		Domains []DomainEntry `json:"domains"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/domains", nil, &out); err != nil {
		return nil, err
	}
	return out.Domains, nil
}

// AddDomain adds an enabled entry to the list named by entry.Type and entry.Kind, with its comment and groups, and
// returns it as Pi-hole saved it (or as sent, if Pi-hole's answer doesn't include it). Pi-hole refusing it (already
// on that list, or not a valid domain or regex) is a RejectedError.
func (c *Client) AddDomain(ctx context.Context, entry DomainEntry) (DomainEntry, error) {
	if err := checkDomainPath(entry.Type, entry.Kind); err != nil {
		return DomainEntry{}, err
	}
	entry.Groups, entry.Enabled = nonNil(entry.Groups), true
	body := struct {
		Domain  string `json:"domain"`
		Comment string `json:"comment"`
		Groups  []int  `json:"groups"`
		Enabled bool   `json:"enabled"`
	}{entry.Domain, entry.Comment, entry.Groups, entry.Enabled}
	var out writeResponse
	if err := c.write(ctx, http.MethodPost, "/api/domains/"+entry.Type+"/"+entry.Kind, body, &out); err != nil {
		return DomainEntry{}, err
	}
	return savedDomain(out, entry), nil
}

// UpdateDomain replaces an entry's comment, groups and enabled flag, and returns it as saved. Domain, Type and Kind
// must match an existing entry exactly: Pi-hole's PUT creates the entry if it doesn't exist, so callers check that it
// does first. Every field is sent, so nothing falls back to Pi-hole's defaults.
func (c *Client) UpdateDomain(ctx context.Context, entry DomainEntry) (DomainEntry, error) {
	if err := checkDomainPath(entry.Type, entry.Kind); err != nil {
		return DomainEntry{}, err
	}
	entry.Groups = nonNil(entry.Groups)
	body := struct {
		Type    string `json:"type"`
		Kind    string `json:"kind"`
		Comment string `json:"comment"`
		Groups  []int  `json:"groups"`
		Enabled bool   `json:"enabled"`
	}{entry.Type, entry.Kind, entry.Comment, entry.Groups, entry.Enabled}
	var out writeResponse
	if err := c.write(ctx, http.MethodPut, domainPath(entry.Type, entry.Kind, entry.Domain), body, &out); err != nil {
		return DomainEntry{}, err
	}
	return savedDomain(out, entry), nil
}

// savedDomain picks the entry Pi-hole returned for sent, falling back to sent itself.
func savedDomain(out writeResponse, sent DomainEntry) DomainEntry {
	for _, d := range out.Domains {
		if d.Domain == sent.Domain && d.Type == sent.Type && d.Kind == sent.Kind {
			return d
		}
	}
	return sent
}

// DeleteDomain removes an entry from the list named by listType and kind.
func (c *Client) DeleteDomain(ctx context.Context, domain, listType, kind string) error {
	if err := checkDomainPath(listType, kind); err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, domainPath(listType, kind, domain), nil, nil)
}

// DatabaseSummary is the response of /api/stats/database/summary: totals for a time window from Pi-hole's
// long-term database, unaffected by FTL restarts.
type DatabaseSummary struct {
	TotalQueries   int     `json:"sum_queries"`
	BlockedQueries int     `json:"sum_blocked"`
	PercentBlocked float64 `json:"percent_blocked"`
	TotalClients   int     `json:"total_clients"`
}

// GetDatabaseSummary returns totals for the window from..until.
func (c *Client) GetDatabaseSummary(ctx context.Context, from, until time.Time) (*DatabaseSummary, error) {
	path := fmt.Sprintf("/api/stats/database/summary?from=%d&until=%d", from.Unix(), until.Unix())
	var out DatabaseSummary
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LiveSummary is the response of /api/stats/summary: in-memory counters since FTL last started. Status and Replies
// break queries down by FTL's result codes (GRAVITY, FORWARDED, CACHE, NXDOMAIN, SERVFAIL and so on).
type LiveSummary struct {
	Queries struct {
		Total          int            `json:"total"`
		Blocked        int            `json:"blocked"`
		PercentBlocked float64        `json:"percent_blocked"`
		UniqueDomains  int            `json:"unique_domains"`
		Forwarded      int            `json:"forwarded"`
		Cached         int            `json:"cached"`
		Status         map[string]int `json:"status"`
		Replies        map[string]int `json:"replies"`
	} `json:"queries"`
	Clients struct {
		Active int `json:"active"`
		Total  int `json:"total"`
	} `json:"clients"`
	Gravity struct {
		DomainsBeingBlocked int `json:"domains_being_blocked"`
	} `json:"gravity"`
}

// GetLiveSummary returns the live counters.
func (c *Client) GetLiveSummary(ctx context.Context) (*LiveSummary, error) {
	var out LiveSummary
	if err := c.do(ctx, http.MethodGet, "/api/stats/summary", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// QueryLogEntry is one entry from /api/queries.
type QueryLogEntry struct {
	ID     int     `json:"id"`
	Time   float64 `json:"time"` // Unix time, fractional seconds
	Type   string  `json:"type"` // record type: A, AAAA, PTR and so on
	Domain string  `json:"domain"`
	Client struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	} `json:"client"`
	Status   string `json:"status"` // GRAVITY, FORWARDED, CACHE, DENYLIST and so on
	DNSSEC   string `json:"dnssec"`
	Upstream string `json:"upstream"`
	Reply    struct {
		Type string  `json:"type"`
		Time float64 `json:"time"` // seconds
	} `json:"reply"`
}

// ListQueries returns the newest length entries of the query log, newest first. length is clamped to 1..1000.
func (c *Client) ListQueries(ctx context.Context, length int) ([]QueryLogEntry, error) {
	length = min(max(length, 1), maxQueryLog)
	var out struct {
		Queries []QueryLogEntry `json:"queries"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/queries?length=%d", length), nil, &out); err != nil {
		return nil, err
	}
	return out.Queries, nil
}

// ClientEntry is one entry from /api/clients. Pi-hole identifies a client by the IP, MAC address, hostname or subnet
// it was added with (Client); ID is Pi-hole's own row ID, for display only. Updates address the client by Client.
type ClientEntry struct {
	ID           int    `json:"id"`
	Client       string `json:"client"`
	Name         string `json:"name"` // resolved hostname, read-only
	Comment      string `json:"comment"`
	Groups       []int  `json:"groups"`
	DateAdded    int64  `json:"date_added"`    // Unix seconds
	DateModified int64  `json:"date_modified"` // Unix seconds
}

// ListClients returns every configured client.
func (c *Client) ListClients(ctx context.Context) ([]ClientEntry, error) {
	var out struct {
		Clients []ClientEntry `json:"clients"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/clients", nil, &out); err != nil {
		return nil, err
	}
	return out.Clients, nil
}

// UpdateClientGroups replaces a client's groups and comment, and returns the client as saved (or nil if Pi-hole's
// answer doesn't include it). clientIdentifier must match the client's existing identifier exactly: Pi-hole's PUT
// creates the client if it doesn't exist, so callers check that it does first.
func (c *Client) UpdateClientGroups(ctx context.Context, clientIdentifier, comment string, groupIDs []int) (*ClientEntry, error) {
	body := struct {
		Client  string `json:"client"`
		Comment string `json:"comment"`
		Groups  []int  `json:"groups"`
	}{clientIdentifier, comment, nonNil(groupIDs)}
	var out writeResponse
	if err := c.write(ctx, http.MethodPut, "/api/clients/"+url.PathEscape(clientIdentifier), body, &out); err != nil {
		return nil, err
	}
	for _, ce := range out.Clients {
		if ce.Client == clientIdentifier {
			return &ce, nil
		}
	}
	return nil, nil
}

// Group is a Pi-hole group (not an instance group).
type Group struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
}

// ListGroups returns Pi-hole's groups.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/groups", nil, &out); err != nil {
		return nil, err
	}
	return out.Groups, nil
}
