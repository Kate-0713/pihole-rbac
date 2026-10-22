// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads the bootstrap configuration: the non-secret settings that come from PIHOLE_RBAC_* environment
// variables and are fixed for the life of the process. Secrets are loaded by internal/secrets, and runtime settings
// live in the database.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Prefix is the prefix of every environment variable the app reads.
const Prefix = "PIHOLE_RBAC_"

const (
	DefaultListen  = ":8080"
	DefaultDataDir = "/var/lib/pihole-rbac"
)

// CookieSecure decides when the session cookie gets the Secure flag.
type CookieSecure int

const (
	// CookieSecureAuto sets Secure when the request arrived over TLS, or a trusted proxy sent X-Forwarded-Proto: https.
	CookieSecureAuto CookieSecure = iota
	CookieSecureAlways
	CookieSecureNever
)

func (c CookieSecure) String() string {
	return [...]string{"auto", "true", "false"}[c]
}

// Config is the bootstrap configuration.
type Config struct {
	Listen         string
	DataDir        string // absolute
	TrustedProxies []netip.Prefix
	CookieSecure   CookieSecure
	LDAPCAFile     string // optional CA bundle for LDAPS
	UpdateCheck    bool
	LogLevel       slog.Level
}

// FromEnv loads the configuration from the process environment.
func FromEnv() (*Config, error) {
	return Load(os.Getenv)
}

// Load reads the configuration through getenv. An empty variable counts as unset. Every invalid variable is reported,
// not just the first.
func Load(getenv func(string) string) (*Config, error) {
	get := func(name string) string { return strings.TrimSpace(getenv(Prefix + name)) }
	c := &Config{
		Listen:      DefaultListen,
		DataDir:     DefaultDataDir,
		UpdateCheck: true,
		LogLevel:    slog.LevelInfo,
	}
	var errs []error
	bad := func(name string, err error) { errs = append(errs, fmt.Errorf("%s%s: %w", Prefix, name, err)) }

	if v := get("LISTEN"); v != "" {
		if err := checkListen(v); err != nil {
			bad("LISTEN", err)
		}
		c.Listen = v
	}
	if v := get("DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if abs, err := filepath.Abs(c.DataDir); err != nil {
		bad("DATA_DIR", err)
	} else {
		c.DataDir = abs
	}
	if v := get("TRUSTED_PROXIES"); v != "" {
		p, err := parsePrefixes(v)
		if err != nil {
			bad("TRUSTED_PROXIES", err)
		}
		c.TrustedProxies = p
	}
	if v := get("COOKIE_SECURE"); v != "" {
		switch strings.ToLower(v) {
		case "auto":
			c.CookieSecure = CookieSecureAuto
		case "true":
			c.CookieSecure = CookieSecureAlways
		case "false":
			c.CookieSecure = CookieSecureNever
		default:
			bad("COOKIE_SECURE", fmt.Errorf("%q is not auto, true or false", v))
		}
	}
	c.LDAPCAFile = get("LDAP_CA_FILE")
	if v := get("UPDATE_CHECK"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			bad("UPDATE_CHECK", fmt.Errorf("%q is not true or false", v))
		}
		c.UpdateCheck = b
	}
	if v := get("LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			bad("LOG_LEVEL", fmt.Errorf("%q is not debug, info, warn or error", v))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return c, nil
}

// IsTrustedProxy reports whether addr is in PIHOLE_RBAC_TRUSTED_PROXIES. Only then may its X-Forwarded-* headers be
// believed.
func (c *Config) IsTrustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func checkListen(v string) error {
	_, port, err := net.SplitHostPort(v)
	if err != nil {
		return err
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	return nil
}

// parsePrefixes reads a comma- or space-separated list of CIDRs. A bare address means just that host.
func parsePrefixes(v string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []netip.Prefix
	var errs []error
	for _, f := range fields {
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if p.Addr().Is4In6() {
				errs = append(errs, fmt.Errorf("%s: write IPv4 ranges in IPv4 form", f))
				continue
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, errors.Join(errs...)
}
