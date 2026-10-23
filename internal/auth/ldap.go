// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// LDAPSettingsKey is the settings row holding the LDAP settings.
const LDAPSettingsKey = "ldap"

// LDAP TLS modes. The CA bundle for "verify" comes from PIHOLE_RBAC_LDAP_CA_FILE when set; otherwise the system's
// trusted CAs are used.
const (
	LDAPTLSVerify   = "verify"
	LDAPTLSInsecure = "insecure" // lab use only: the server's certificate isn't checked at all
)

// ldapTimeout bounds connecting to the server and each operation, so an unreachable LDAP server can't hold a login
// request (and the local login after it) for long.
const ldapTimeout = 10 * time.Second

// LDAPSettings are the LDAP runtime settings stored in the database. The bind password is a tier 1 secret
// (PIHOLE_RBAC_LDAP_BIND_PASSWORD) and is never stored here.
type LDAPSettings struct {
	URL        string `json:"url"`         // ldaps://dc01.example.local:636, or ldap:// (passwords then cross the network in the clear)
	BindDN     string `json:"bind_dn"`     // read-only service account used to find users and their groups
	BaseDN     string `json:"base_dn"`     // users and groups are searched for under this DN
	UserFilter string `json:"user_filter"` // finds a user by username, e.g. (sAMAccountName=%s) or (uid=%s)
	TLSMode    string `json:"tls_mode"`    // LDAPTLSVerify (default) or LDAPTLSInsecure
	// AllowCNFallback accepts a certificate whose Common Name, rather than a Subject Alternative Name, matches the
	// host, for older internal CAs. The chain, expiry and trust are still checked. Only applies with a CA file. It
	// weakens hostname checking slightly, so it is off unless an admin turns it on (v1 had it on by default).
	AllowCNFallback bool `json:"allow_cn_fallback,omitempty"`
}

// Validate checks the settings without contacting the server.
func (s LDAPSettings) Validate() error {
	u, err := url.Parse(s.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("url must look like ldaps://host[:port] or ldap://host[:port]")
	}
	if _, err := ldap.ParseDN(s.BindDN); err != nil || s.BindDN == "" {
		return fmt.Errorf("bind_dn is not a valid DN")
	}
	if _, err := ldap.ParseDN(s.BaseDN); err != nil || s.BaseDN == "" {
		return fmt.Errorf("base_dn is not a valid DN")
	}
	// The username is substituted for the single %s, after escaping. Any other % would be a format verb.
	if strings.Count(s.UserFilter, "%s") != 1 || strings.Count(s.UserFilter, "%") != 1 {
		return fmt.Errorf("user_filter must contain %%s exactly once and no other %%, e.g. (uid=%%s)")
	}
	if _, err := ldap.CompileFilter(fmt.Sprintf(s.UserFilter, "x")); err != nil {
		return fmt.Errorf("user_filter is not a valid LDAP filter: %w", err)
	}
	switch s.TLSMode {
	case "", LDAPTLSVerify, LDAPTLSInsecure:
	default:
		return fmt.Errorf("tls_mode must be %q or %q", LDAPTLSVerify, LDAPTLSInsecure)
	}
	return nil
}

// LoadLDAPSettings reads the LDAP settings. found is false if none have been saved.
func LoadLDAPSettings(ctx context.Context, q *db.Queries) (s LDAPSettings, found bool, err error) {
	row, err := q.GetSetting(ctx, LDAPSettingsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return LDAPSettings{}, false, nil
	}
	if err != nil {
		return LDAPSettings{}, false, err
	}
	if err := json.Unmarshal([]byte(row.Value), &s); err != nil {
		return LDAPSettings{}, true, fmt.Errorf("settings %q: %w", LDAPSettingsKey, err)
	}
	if err := s.Validate(); err != nil {
		return LDAPSettings{}, true, fmt.Errorf("settings %q: %w", LDAPSettingsKey, err)
	}
	return s, true, nil
}

// ldapConn is the part of *ldap.Conn the authenticator uses, so tests can stand in for a directory.
type ldapConn interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPAuthenticator verifies credentials against an LDAP server and returns the user's DN and group DNs. Which
// roles those groups give is decided by the caller. The user's password is only used for the bind; it is never
// stored or logged.
type LDAPAuthenticator struct {
	s            LDAPSettings
	bindPassword func() (secrets.Value, bool)
	dial         func() (ldapConn, error)
}

// NewLDAPAuthenticator builds an authenticator. bindPassword is called on every login, so a reloaded
// PIHOLE_RBAC_LDAP_BIND_PASSWORD takes effect at once. caFile is PIHOLE_RBAC_LDAP_CA_FILE, or "".
func NewLDAPAuthenticator(s LDAPSettings, bindPassword func() (secrets.Value, bool), caFile string) (*LDAPAuthenticator, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	tlsCfg, err := ldapTLSConfig(s, caFile)
	if err != nil {
		return nil, err
	}
	a := &LDAPAuthenticator{s: s, bindPassword: bindPassword}
	a.dial = func() (ldapConn, error) {
		opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: ldapTimeout})}
		if tlsCfg != nil {
			opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
		}
		conn, err := ldap.DialURL(s.URL, opts...)
		if err != nil {
			return nil, fmt.Errorf("connecting to LDAP: %w", err)
		}
		conn.SetTimeout(ldapTimeout)
		return conn, nil
	}
	return a, nil
}

// ldapTLSConfig returns the TLS config for the three modes kept from v1: skip verification, verify against the
// system CAs plus an internal CA (accepting a Common Name match only if AllowCNFallback is set), or the system
// defaults (nil).
func ldapTLSConfig(s LDAPSettings, caFile string) (*tls.Config, error) {
	if s.TLSMode == LDAPTLSInsecure {
		return &tls.Config{InsecureSkipVerify: true}, nil // #nosec G402 -- explicit, documented lab-only setting
	}
	if caFile == "" {
		return nil, nil
	}
	pool, err := loadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	if s.AllowCNFallback {
		u, _ := url.Parse(s.URL) // validated already
		return tlsConfigWithCNFallback(pool, u.Hostname()), nil
	}
	return &tls.Config{RootCAs: pool}, nil
}

// loadCAPool builds a pool of the system's trusted CAs plus the internal CA, so a public LDAP endpoint still works.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("PIHOLE_RBAC_LDAP_CA_FILE: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("PIHOLE_RBAC_LDAP_CA_FILE: %s contains no PEM certificate", caFile)
	}
	return pool, nil
}

// tlsConfigWithCNFallback validates the server's chain against pool (trust and expiry, as Go normally does), and
// accepts the host in either a Subject Alternative Name or, failing that, the legacy Common Name. Go stopped
// accepting a Common Name alone in 1.15, which breaks older internal CAs outright. Nothing else
// InsecureSkipVerify would turn off is skipped.
func tlsConfigWithCNFallback(pool *x509.CertPool, host string) *tls.Config {
	return &tls.Config{
		RootCAs: pool,
		// Verification happens in VerifyConnection; crypto/tls's own check would fail on a CN-only certificate.
		InsecureSkipVerify: true, // #nosec G402 -- replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("server presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates}); err != nil {
				return fmt.Errorf("certificate chain is not trusted: %w", err)
			}
			if leaf.VerifyHostname(host) == nil || strings.EqualFold(leaf.Subject.CommonName, host) {
				return nil
			}
			return fmt.Errorf("certificate is not valid for %q (Common Name %q, SANs %v)", host, leaf.Subject.CommonName, leaf.DNSNames)
		},
	}
}

// ErrNoSuchUser is returned by Lookup when the directory has no single entry for the username: the user is gone, or
// the filter matches several entries, which at login is refused as well.
var ErrNoSuchUser = errors.New("no such user in the directory")

// Authenticate binds as the service account, finds the user's DN with the escaped username, binds as the user to
// check the password, binds back as the service account and searches for the groups that list the user as a member
// (memberOf isn't reliably present across directories).
func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	username = NormalizeUsername(username)
	// An empty password would be an unauthenticated bind, which many servers accept.
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	conn, bindPW, err := a.serviceConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userDN, err := a.findUser(conn, username)
	if errors.Is(err, ErrNoSuchUser) {
		// No such user, or an ambiguous filter: either way, don't reveal which.
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user bind failed: %w", err)
	}

	if err := conn.Bind(a.s.BindDN, bindPW.Reveal()); err != nil {
		return nil, fmt.Errorf("service account rebind failed: %w", err)
	}
	return a.identity(conn, username, userDN)
}

// Lookup finds a user's current DN and groups with the service account alone, for rechecking the roles of a user who
// is already logged in. No password is involved, so nothing is bound as the user. It returns ErrNoSuchUser if the
// directory no longer has exactly one entry for the username, and any other error if the directory couldn't be asked.
func (a *LDAPAuthenticator) Lookup(ctx context.Context, username string) (*Identity, error) {
	username = NormalizeUsername(username)
	if username == "" {
		return nil, ErrNoSuchUser
	}
	conn, _, err := a.serviceConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	userDN, err := a.findUser(conn, username)
	if err != nil {
		return nil, err
	}
	return a.identity(conn, username, userDN)
}

// serviceConn connects and binds as the service account. The bind password is returned for a later rebind.
func (a *LDAPAuthenticator) serviceConn(ctx context.Context) (ldapConn, secrets.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, secrets.Value{}, err
	}
	bindPW, ok := a.bindPassword()
	if !ok {
		return nil, secrets.Value{}, errors.New("PIHOLE_RBAC_LDAP_BIND_PASSWORD is not set")
	}
	conn, err := a.dial()
	if err != nil {
		return nil, secrets.Value{}, err
	}
	if err := conn.Bind(a.s.BindDN, bindPW.Reveal()); err != nil {
		conn.Close()
		return nil, secrets.Value{}, fmt.Errorf("service account bind failed: %w", err)
	}
	return conn, bindPW, nil
}

// findUser returns the DN of the one entry the user filter finds for username, or ErrNoSuchUser.
func (a *LDAPAuthenticator) findUser(conn ldapConn, username string) (string, error) {
	res, err := conn.Search(ldap.NewSearchRequest(
		a.s.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(a.s.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn"}, nil,
	))
	if err != nil {
		return "", fmt.Errorf("user search failed: %w", err)
	}
	if len(res.Entries) != 1 {
		return "", ErrNoSuchUser
	}
	return res.Entries[0].DN, nil
}

// identity searches for the groups that list userDN as a member. conn must be bound as the service account.
func (a *LDAPAuthenticator) identity(conn ldapConn, username, userDN string) (*Identity, error) {
	groups, err := conn.Search(ldap.NewSearchRequest(
		a.s.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN)),
		[]string{"dn"}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("group search failed: %w", err)
	}
	id := &Identity{Username: username, Source: MethodLDAP, DN: userDN, Groups: make([]string, 0, len(groups.Entries))}
	for _, e := range groups.Entries {
		id.Groups = append(id.Groups, e.DN)
	}
	return id, nil
}
