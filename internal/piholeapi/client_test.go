// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

const password = "correct horse battery staple"

func newClient(t *testing.T, baseURL string, opts ...func(*piholeapi.Options)) *piholeapi.Client {
	t.Helper()
	o := piholeapi.Options{BaseURL: baseURL, Password: secrets.NewValue([]byte(password))}
	for _, f := range opts {
		f(&o)
	}
	c, err := piholeapi.New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func TestParseBaseURL(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  string
	}{
		{in: "http://pi.hole", want: "http://pi.hole"},
		{in: "  https://10.0.0.2:8443/  ", want: "https://10.0.0.2:8443"},
		{in: "https://proxy.example/pihole1/", want: "https://proxy.example/pihole1"},
		{in: "https://[fd00::2]", want: "https://[fd00::2]"},
		{in: "ftp://pi.hole", wantErr: "http:// or https://"},
		{in: "pi.hole", wantErr: "http:// or https://"},
		{in: "https://", wantErr: "no host"},
		{in: "https://:443", wantErr: "no host"},
		{in: "https://user:pw@pi.hole", wantErr: "username or password"},
		{in: "https://pi.hole/?x=1", wantErr: "query or fragment"},
		{in: "https://pi.hole/?", wantErr: "query or fragment"},
		{in: "https://pi.hole/#top", wantErr: "query or fragment"},
		{in: "https://pi.hole:0", wantErr: "invalid port"},
		{in: "https://pi.hole:70000", wantErr: "invalid port"},
		{in: "https://pi.hole/admin/", wantErr: "without /admin or /api"},
		{in: "https://pi.hole/API", wantErr: "without /admin or /api"},
		{in: "::nonsense", wantErr: "not a valid URL"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := piholeapi.ParseBaseURL(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseBaseURL(%q) = %q, %v; want error containing %q", tt.in, got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseBaseURL(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	pw := secrets.NewValue([]byte(password))
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		opts piholeapi.Options
	}{
		{"bad url", piholeapi.Options{BaseURL: "pi.hole", Password: pw}},
		{"empty password", piholeapi.Options{BaseURL: "http://pi.hole"}},
		{"unknown tls mode", piholeapi.Options{BaseURL: "https://pi.hole", Password: pw, TLSMode: "sometimes"}},
		{"ca file with insecure", piholeapi.Options{BaseURL: "https://pi.hole", Password: pw, TLSMode: piholeapi.TLSInsecure, CAFile: notPEM}},
		{"missing ca file", piholeapi.Options{BaseURL: "https://pi.hole", Password: pw, CAFile: filepath.Join(dir, "missing.pem")}},
		{"ca file without pem", piholeapi.Options{BaseURL: "https://pi.hole", Password: pw, CAFile: notPEM}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := piholeapi.New(tt.opts); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}

func TestSessionReuse(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		validity   int
		between    func(*piholetest.Server)
		wantLogins int
	}{
		{name: "cached session is reused", validity: 1800, wantLogins: 1},
		{name: "expiring session logs in again", validity: 0, wantLogins: 2},
		{name: "session forgotten by pihole logs in again", validity: 1800, between: (*piholetest.Server).ForgetSessions, wantLogins: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			ph.SetValidity(tt.validity)
			c := newClient(t, ph.URL)
			if _, err := c.GetStatus(ctx); err != nil {
				t.Fatalf("first call: %v", err)
			}
			if tt.between != nil {
				tt.between(ph)
			}
			if err := c.SetBlocking(ctx, false); err != nil {
				t.Fatalf("second call: %v", err)
			}
			if got := ph.Logins(); got != tt.wantLogins {
				t.Errorf("logins = %d, want %d", got, tt.wantLogins)
			}
		})
	}
}

func TestErrorKinds(t *testing.T) {
	closed := piholetest.New(t, password)
	closedURL := closed.URL
	closed.Close()

	tests := []struct {
		name     string
		url      func(t *testing.T) string
		password string
		ctx      func() context.Context
		wantIs   error
		wantKind string
		wantDown bool
	}{
		{
			name:     "wrong password",
			url:      func(t *testing.T) string { return piholetest.New(t, password).URL },
			password: "wrong",
			wantIs:   piholeapi.ErrAuthRejected, wantKind: piholeapi.CodeAuthRejected, wantDown: true,
		},
		{
			name:   "unreachable",
			url:    func(*testing.T) string { return closedURL },
			wantIs: piholeapi.ErrUnreachable, wantKind: piholeapi.CodeUnreachable, wantDown: true,
		},
		{
			name: "status error",
			url: func(t *testing.T) string {
				ph := piholetest.New(t, password)
				ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
					http.Error(w, "boom", http.StatusInternalServerError)
					return true
				})
				return ph.URL
			},
			wantKind: piholeapi.CodeStatusError,
		},
		{
			name: "bad response",
			url: func(t *testing.T) string {
				ph := piholetest.New(t, password)
				ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
					_, _ = w.Write([]byte("<html>not json</html>"))
					return true
				})
				return ph.URL
			},
			wantIs: piholeapi.ErrBadResponse, wantKind: piholeapi.CodeStatusError,
		},
		{
			name: "cancelled by caller",
			url:  func(t *testing.T) string { return piholetest.New(t, password).URL },
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantIs: context.Canceled, wantKind: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pw := password
			if tt.password != "" {
				pw = tt.password
			}
			c, err := piholeapi.New(piholeapi.Options{BaseURL: tt.url(t), Password: secrets.NewValue([]byte(pw))})
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx()
			}
			_, err = c.GetStatus(ctx)
			if err == nil {
				t.Fatal("GetStatus succeeded, want an error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error %v is not %v", err, tt.wantIs)
			}
			if tt.name == "status error" {
				var se *piholeapi.StatusError
				if !errors.As(err, &se) || se.Code != http.StatusInternalServerError {
					t.Errorf("error %v is not a 500 StatusError", err)
				}
			}
			if got := piholeapi.Kind(err); got != tt.wantKind {
				t.Errorf("Kind = %q, want %q", got, tt.wantKind)
			}
			if got := piholeapi.Down(err); got != tt.wantDown {
				t.Errorf("Down = %v, want %v", got, tt.wantDown)
			}
			if strings.Contains(err.Error(), pw) {
				t.Errorf("error %q contains the password", err)
			}
		})
	}
}

// A redirect must not carry the session ID, or on login the password, to another server.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)

	t.Run("login", func(t *testing.T) {
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}))
		t.Cleanup(redirector.Close)
		_, err := newClient(t, redirector.URL).GetStatus(context.Background())
		if piholeapi.Kind(err) != piholeapi.CodeStatusError {
			t.Errorf("err = %v, want a status error", err)
		}
	})
	t.Run("request", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
			return true
		})
		_, err := newClient(t, ph.URL).GetStatus(context.Background())
		var se *piholeapi.StatusError
		if !errors.As(err, &se) || se.Code != http.StatusFound {
			t.Errorf("err = %v, want a 302 StatusError", err)
		}
	})
	if n := hits.Load(); n != 0 {
		t.Errorf("the redirect target was called %d times", n)
	}
}

func TestCloseLogsOut(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	c, err := piholeapi.New(piholeapi.Options{BaseURL: ph.URL, Password: secrets.NewValue([]byte(password))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ph.Sessions() != 0 || ph.Logouts() != 1 {
		t.Errorf("after Close: %d sessions, %d logouts; want 0 and 1", ph.Sessions(), ph.Logouts())
	}
	if _, err := c.GetStatus(ctx); !errors.Is(err, piholeapi.ErrClosed) {
		t.Errorf("call after Close: %v, want ErrClosed", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if ph.Logins() != 1 {
		t.Errorf("logins = %d, want 1", ph.Logins())
	}
}

func TestTLSModes(t *testing.T) {
	ph := piholetest.NewTLS(t, password)
	caFile := filepath.Join(t.TempDir(), "pihole-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ph.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mode    piholeapi.TLSMode
		caFile  string
		wantErr error
	}{
		{name: "verify without the CA fails", mode: piholeapi.TLSVerify, wantErr: piholeapi.ErrUnreachable},
		{name: "verify with the CA file", mode: piholeapi.TLSVerify, caFile: caFile},
		{name: "insecure", mode: piholeapi.TLSInsecure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newClient(t, ph.URL, func(o *piholeapi.Options) { o.TLSMode, o.CAFile = tt.mode, tt.caFile })
			_, err := c.GetStatus(context.Background())
			if tt.wantErr == nil && err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetStatus: %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDomainPathsAreWhitelisted(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	var calls atomic.Int32
	ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		calls.Add(1)
		w.WriteHeader(http.StatusCreated)
		return true
	})
	c := newClient(t, ph.URL)
	tests := []struct {
		name string
		call func() error
		ok   bool
	}{
		{"add allow exact", func() error {
			return c.AddDomain(ctx, piholeapi.DomainEntry{Domain: "example.com", Type: "allow", Kind: "exact"})
		}, true},
		{"add bad type", func() error {
			return c.AddDomain(ctx, piholeapi.DomainEntry{Domain: "example.com", Type: "allow/../../auth", Kind: "exact"})
		}, false},
		{"update bad kind", func() error {
			return c.UpdateDomainGroups(ctx, "example.com", "deny", "glob", "", nil)
		}, false},
		{"update deny regex", func() error {
			return c.UpdateDomainGroups(ctx, `^ads?\.`, "deny", "regex", "", nil)
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := calls.Load()
			err := tt.call()
			if tt.ok && err != nil {
				t.Fatalf("call: %v", err)
			}
			if !tt.ok {
				if !errors.Is(err, piholeapi.ErrInvalidArgument) {
					t.Fatalf("call: %v, want ErrInvalidArgument", err)
				}
				if calls.Load() != before {
					t.Error("an invalid call reached Pi-hole")
				}
			}
		})
	}
}

func TestPathValuesAreEscaped(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	var got []string
	ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		got = append(got, r.URL.EscapedPath()+"?"+r.URL.RawQuery)
		_, _ = w.Write([]byte(`{}`))
		return true
	})
	c := newClient(t, ph.URL)
	if err := c.UpdateClientGroups(ctx, "10.0.0.0/24", "lab", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateDomainGroups(ctx, "a/b?c", "deny", "exact", "", []int{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListQueries(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/api/clients/10.0.0.0%2F24?",
		"/api/domains/deny/exact/a%2Fb%3Fc?",
		"/api/queries?length=1000",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("paths:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
