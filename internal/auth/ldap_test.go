// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func validLDAPSettings() LDAPSettings {
	return LDAPSettings{
		URL:        "ldaps://dc01.example.local:636",
		BindDN:     "cn=svc-pihole,ou=service,dc=example,dc=local",
		BaseDN:     "dc=example,dc=local",
		UserFilter: "(sAMAccountName=%s)",
	}
}

func TestLDAPSettingsValidate(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*LDAPSettings)
		ok     bool
	}{
		{"valid", func(*LDAPSettings) {}, true},
		{"plain ldap allowed", func(s *LDAPSettings) { s.URL = "ldap://dc01:389" }, true},
		{"insecure mode", func(s *LDAPSettings) { s.TLSMode = LDAPTLSInsecure }, true},
		{"http url", func(s *LDAPSettings) { s.URL = "http://dc01" }, false},
		{"no host", func(s *LDAPSettings) { s.URL = "ldaps://" }, false},
		{"url with path", func(s *LDAPSettings) { s.URL = "ldaps://dc01/dc=x" }, false},
		{"empty bind dn", func(s *LDAPSettings) { s.BindDN = "" }, false},
		{"bad base dn", func(s *LDAPSettings) { s.BaseDN = "not a dn" }, false},
		{"filter without %s", func(s *LDAPSettings) { s.UserFilter = "(uid=alice)" }, false},
		{"filter with two %s", func(s *LDAPSettings) { s.UserFilter = "(|(uid=%s)(cn=%s))" }, false},
		{"filter with another verb", func(s *LDAPSettings) { s.UserFilter = "(uid=%s%d)" }, false},
		{"filter not a filter", func(s *LDAPSettings) { s.UserFilter = "uid=%s" }, false},
		{"unknown tls mode", func(s *LDAPSettings) { s.TLSMode = "starttls" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validLDAPSettings()
			tt.modify(&s)
			if err := s.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestLoadLDAPSettings(t *testing.T) {
	e := newSessionEnv(t, SessionOptions{})
	ctx := context.Background()
	if _, found, err := LoadLDAPSettings(ctx, e.st.Read()); found || err != nil {
		t.Fatalf("nothing saved: found=%v err=%v", found, err)
	}
	save := func(v string) {
		t.Helper()
		if err := e.st.WithTx(ctx, func(q *db.Queries) error {
			return q.UpsertSetting(ctx, db.UpsertSettingParams{Key: LDAPSettingsKey, Value: v})
		}); err != nil {
			t.Fatal(err)
		}
	}
	save(`{"url":"ldaps://dc01","bind_dn":"cn=svc,dc=x","base_dn":"dc=x","user_filter":"(uid=%s)"}`)
	s, found, err := LoadLDAPSettings(ctx, e.st.Read())
	if !found || err != nil || s.URL != "ldaps://dc01" || s.UserFilter != "(uid=%s)" || s.AllowCNFallback {
		t.Fatalf("got %+v found=%v err=%v (CN fallback must be off when not saved)", s, found, err)
	}
	save(`{"url":"ldaps://dc01","bind_dn":"cn=svc,dc=x","base_dn":"dc=x","user_filter":"(uid=%s)","allow_cn_fallback":true}`)
	if s, _, err := LoadLDAPSettings(ctx, e.st.Read()); err != nil || !s.AllowCNFallback {
		t.Fatalf("CN fallback turned on: got %+v, %v", s, err)
	}
	save(`{"url":"http://dc01","bind_dn":"cn=svc,dc=x","base_dn":"dc=x","user_filter":"(uid=%s)"}`)
	if _, found, err := LoadLDAPSettings(ctx, e.st.Read()); !found || err == nil {
		t.Fatalf("invalid saved settings: found=%v err=%v", found, err)
	}
}

// fakeDirectory is an in-memory LDAP server: users by DN with passwords, and groups by DN with member DNs.
type fakeDirectory struct {
	svcDN, svcPW string
	users        map[string]string   // DN -> password
	uids         map[string][]string // username -> matching user DNs
	groups       map[string][]string // group DN -> member DNs
	dialErr      error
	searchErr    error

	binds   []string // DNs bound as, in order
	filters []string // search filters, in order
	closed  bool
}

func (d *fakeDirectory) Bind(dn, pw string) error {
	d.binds = append(d.binds, dn)
	if dn == d.svcDN && pw == d.svcPW {
		return nil
	}
	if want, ok := d.users[dn]; ok && pw == want {
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (d *fakeDirectory) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.filters = append(d.filters, r.Filter)
	if d.searchErr != nil {
		return nil, d.searchErr
	}
	res := &ldap.SearchResult{}
	if v, ok := strings.CutPrefix(r.Filter, "(sAMAccountName="); ok {
		v = strings.TrimSuffix(v, ")")
		for uid, dns := range d.uids {
			if ldap.EscapeFilter(uid) == v {
				for _, dn := range dns {
					res.Entries = append(res.Entries, &ldap.Entry{DN: dn})
				}
			}
		}
		return res, nil
	}
	if v, ok := strings.CutPrefix(r.Filter, "(member="); ok {
		v = strings.TrimSuffix(v, ")")
		for g, members := range d.groups {
			for _, m := range members {
				if ldap.EscapeFilter(m) == v {
					res.Entries = append(res.Entries, &ldap.Entry{DN: g})
				}
			}
		}
	}
	slices.SortFunc(res.Entries, func(a, b *ldap.Entry) int { return strings.Compare(a.DN, b.DN) })
	return res, nil
}

func (d *fakeDirectory) Close() error { d.closed = true; return nil }

const aliceDN = "CN=Alice Smith,OU=Staff,DC=example,DC=local"

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		svcDN: validLDAPSettings().BindDN, svcPW: "svc-secret",
		users: map[string]string{aliceDN: "alice-ldap-pw"},
		uids:  map[string][]string{"alice": {aliceDN}},
		groups: map[string][]string{
			"CN=Pihole-Admin,OU=Groups,DC=example,DC=local": {aliceDN},
			"CN=Everyone,OU=Groups,DC=example,DC=local":     {aliceDN, "CN=Bob,DC=example,DC=local"},
			"CN=Other,OU=Groups,DC=example,DC=local":        {"CN=Bob,DC=example,DC=local"},
		},
	}
}

func ldapAuthWith(t *testing.T, d *fakeDirectory, bindPW string) *LDAPAuthenticator {
	t.Helper()
	a, err := NewLDAPAuthenticator(validLDAPSettings(), func() (secrets.Value, bool) {
		return secrets.NewValue([]byte(bindPW)), bindPW != ""
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	a.dial = func() (ldapConn, error) {
		if d.dialErr != nil {
			return nil, d.dialErr
		}
		return d, nil
	}
	return a
}

func TestLDAPAuthenticateSuccess(t *testing.T) {
	d := newFakeDirectory()
	id, err := ldapAuthWith(t, d, "svc-secret").Authenticate(context.Background(), " Alice ", "alice-ldap-pw")
	if err != nil {
		t.Fatal(err)
	}
	wantGroups := []string{"CN=Everyone,OU=Groups,DC=example,DC=local", "CN=Pihole-Admin,OU=Groups,DC=example,DC=local"}
	if id.Username != "alice" || id.Source != MethodLDAP || id.DN != aliceDN || !slices.Equal(id.Groups, wantGroups) || id.UserID != 0 {
		t.Fatalf("identity = %+v", id)
	}
	// Service bind, user bind, then back to the service account for the group search.
	if !slices.Equal(d.binds, []string{d.svcDN, aliceDN, d.svcDN}) {
		t.Fatalf("binds = %v", d.binds)
	}
	if !d.closed {
		t.Fatal("connection not closed")
	}
}

func TestLDAPAuthenticateFailures(t *testing.T) {
	tests := []struct {
		name        string
		user, pw    string
		bindPW      string
		modify      func(*fakeDirectory)
		invalid     bool // want ErrInvalidCredentials (otherwise an operational error)
		wantNoBinds bool
	}{
		{name: "wrong password", user: "alice", pw: "nope", bindPW: "svc-secret", invalid: true},
		{name: "unknown user", user: "mallory", pw: "x", bindPW: "svc-secret", invalid: true},
		{name: "empty password never binds", user: "alice", pw: "", bindPW: "svc-secret", invalid: true, wantNoBinds: true},
		{name: "ambiguous filter", user: "alice", pw: "alice-ldap-pw", bindPW: "svc-secret", invalid: true,
			modify: func(d *fakeDirectory) {
				d.uids["alice"] = append(d.uids["alice"], "CN=Other Alice,DC=example,DC=local")
			}},
		{name: "wrong service password", user: "alice", pw: "alice-ldap-pw", bindPW: "wrong"},
		{name: "no service password", user: "alice", pw: "alice-ldap-pw", bindPW: "", wantNoBinds: true},
		{name: "server unreachable", user: "alice", pw: "alice-ldap-pw", bindPW: "svc-secret", wantNoBinds: true,
			modify: func(d *fakeDirectory) { d.dialErr = errors.New("connecting to LDAP: i/o timeout") }},
		{name: "search fails", user: "alice", pw: "alice-ldap-pw", bindPW: "svc-secret",
			modify: func(d *fakeDirectory) { d.searchErr = errors.New("busy") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newFakeDirectory()
			if tt.modify != nil {
				tt.modify(d)
			}
			id, err := ldapAuthWith(t, d, tt.bindPW).Authenticate(context.Background(), tt.user, tt.pw)
			if err == nil || id != nil {
				t.Fatalf("got %+v, %v; want an error", id, err)
			}
			if errors.Is(err, ErrInvalidCredentials) != tt.invalid {
				t.Fatalf("err = %v; invalid credentials = %v, want %v", err, errors.Is(err, ErrInvalidCredentials), tt.invalid)
			}
			if tt.wantNoBinds && len(d.binds) != 0 {
				t.Fatalf("bound %v", d.binds)
			}
			if strings.Contains(err.Error(), "svc-secret") || strings.Contains(err.Error(), "alice-ldap-pw") {
				t.Fatalf("error leaks a password: %v", err)
			}
		})
	}
}

func TestLDAPFiltersAreEscaped(t *testing.T) {
	d := newFakeDirectory()
	weird := `CN=Bob (Admin)\, Jr,OU=Staff,DC=example,DC=local`
	d.users[weird] = "bob-pw"
	d.uids["bob*)(uid=*"] = []string{weird}
	if _, err := ldapAuthWith(t, d, "svc-secret").Authenticate(context.Background(), "bob*)(uid=*", "bob-pw"); err != nil {
		t.Fatal(err)
	}
	for _, f := range d.filters {
		if strings.Contains(f, "*)(uid=*") || strings.Contains(f, "(Admin)") {
			t.Fatalf("unescaped filter %q", f)
		}
	}
	if d.filters[0] != `(sAMAccountName=bob\2a\29\28uid=\2a)` {
		t.Fatalf("user filter = %q", d.filters[0])
	}
}

// testCA is a throwaway CA for the TLS tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) leaf(t *testing.T, cn string, sans []string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: sans,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestTLSConfigWithCNFallback(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	verify := tlsConfigWithCNFallback(pool, "dc01.example.local").VerifyConnection
	later := time.Now().Add(time.Hour)

	tests := []struct {
		name string
		cert *x509.Certificate
		ok   bool
	}{
		{"SAN matches", ca.leaf(t, "whatever", []string{"dc01.example.local"}, later), true},
		{"CN only matches", ca.leaf(t, "DC01.example.local", nil, later), true},
		{"neither matches", ca.leaf(t, "dc02.example.local", []string{"dc02.example.local"}, later), false},
		{"untrusted CA", other.leaf(t, "dc01.example.local", []string{"dc01.example.local"}, later), false},
		{"expired", ca.leaf(t, "dc01.example.local", nil, time.Now().Add(-time.Minute)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verify(tls.ConnectionState{PeerCertificates: []*x509.Certificate{tt.cert}})
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	if verify(tls.ConnectionState{}) == nil {
		t.Fatal("no certificate accepted")
	}
}

func TestLDAPTLSModes(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, newTestCA(t).pem, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		modify  func(*LDAPSettings)
		caFile  string
		check   func(*tls.Config) bool
		wantErr bool
	}{
		{"system defaults", func(*LDAPSettings) {}, "", func(c *tls.Config) bool { return c == nil }, false},
		{"insecure", func(s *LDAPSettings) { s.TLSMode = LDAPTLSInsecure }, "", func(c *tls.Config) bool {
			return c.InsecureSkipVerify && c.VerifyConnection == nil
		}, false},
		{"CA, CN fallback off by default", func(*LDAPSettings) {}, caFile, func(c *tls.Config) bool {
			return !c.InsecureSkipVerify && c.VerifyConnection == nil && c.RootCAs != nil
		}, false},
		{"CA with CN fallback turned on", func(s *LDAPSettings) { s.AllowCNFallback = true }, caFile, func(c *tls.Config) bool {
			return c.VerifyConnection != nil && c.RootCAs != nil
		}, false},
		{"CN fallback without a CA file has no effect", func(s *LDAPSettings) { s.AllowCNFallback = true }, "", func(c *tls.Config) bool {
			return c == nil
		}, false},
		{"missing CA file", func(*LDAPSettings) {}, filepath.Join(t.TempDir(), "nope.pem"), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validLDAPSettings()
			tt.modify(&s)
			c, err := ldapTLSConfig(s, tt.caFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !tt.check(c) {
				t.Fatalf("config = %+v", c)
			}
		})
	}

	notPEM := filepath.Join(t.TempDir(), "x.pem")
	_ = os.WriteFile(notPEM, []byte("hello"), 0o600)
	if _, err := ldapTLSConfig(validLDAPSettings(), notPEM); err == nil {
		t.Fatal("a file with no certificate was accepted")
	}
}
