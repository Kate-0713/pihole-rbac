// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"log/slog"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	wantDir, _ := filepath.Abs(DefaultDataDir)
	if c.Listen != ":8080" || c.DataDir != wantDir || c.CookieSecure != CookieSecureAuto ||
		!c.UpdateCheck || c.LogLevel != slog.LevelInfo || len(c.TrustedProxies) != 0 || c.LDAPCAFile != "" ||
		c.LogDir != "" || c.LogRetentionDays != DefaultLogRetentionDays {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		check   func(t *testing.T, c *Config)
		wantErr string // substring; "" means no error
	}{
		{name: "listen", env: map[string]string{"PIHOLE_RBAC_LISTEN": "127.0.0.1:9000"},
			check: func(t *testing.T, c *Config) {
				if c.Listen != "127.0.0.1:9000" {
					t.Errorf("Listen = %q", c.Listen)
				}
			}},
		{name: "listen without port", env: map[string]string{"PIHOLE_RBAC_LISTEN": "8080"}, wantErr: "PIHOLE_RBAC_LISTEN"},
		{name: "listen bad port", env: map[string]string{"PIHOLE_RBAC_LISTEN": ":99999"}, wantErr: "invalid port"},
		{name: "empty means unset", env: map[string]string{"PIHOLE_RBAC_LISTEN": "  "},
			check: func(t *testing.T, c *Config) {
				if c.Listen != DefaultListen {
					t.Errorf("Listen = %q", c.Listen)
				}
			}},
		{name: "relative data dir made absolute", env: map[string]string{"PIHOLE_RBAC_DATA_DIR": ".devdata"},
			check: func(t *testing.T, c *Config) {
				if !filepath.IsAbs(c.DataDir) || filepath.Base(c.DataDir) != ".devdata" {
					t.Errorf("DataDir = %q", c.DataDir)
				}
			}},
		{name: "cookie secure", env: map[string]string{"PIHOLE_RBAC_COOKIE_SECURE": "TRUE"},
			check: func(t *testing.T, c *Config) {
				if c.CookieSecure != CookieSecureAlways {
					t.Errorf("CookieSecure = %v", c.CookieSecure)
				}
			}},
		{name: "cookie secure false", env: map[string]string{"PIHOLE_RBAC_COOKIE_SECURE": "false"},
			check: func(t *testing.T, c *Config) {
				if c.CookieSecure != CookieSecureNever {
					t.Errorf("CookieSecure = %v", c.CookieSecure)
				}
			}},
		{name: "cookie secure invalid", env: map[string]string{"PIHOLE_RBAC_COOKIE_SECURE": "yes"}, wantErr: "PIHOLE_RBAC_COOKIE_SECURE"},
		{name: "update check off", env: map[string]string{"PIHOLE_RBAC_UPDATE_CHECK": "false"},
			check: func(t *testing.T, c *Config) {
				if c.UpdateCheck {
					t.Error("UpdateCheck = true")
				}
			}},
		{name: "update check invalid", env: map[string]string{"PIHOLE_RBAC_UPDATE_CHECK": "nah"}, wantErr: "PIHOLE_RBAC_UPDATE_CHECK"},
		{name: "log level", env: map[string]string{"PIHOLE_RBAC_LOG_LEVEL": "DEBUG"},
			check: func(t *testing.T, c *Config) {
				if c.LogLevel != slog.LevelDebug {
					t.Errorf("LogLevel = %v", c.LogLevel)
				}
			}},
		{name: "log level invalid", env: map[string]string{"PIHOLE_RBAC_LOG_LEVEL": "loud"}, wantErr: "PIHOLE_RBAC_LOG_LEVEL"},
		{name: "log dir made absolute", env: map[string]string{"PIHOLE_RBAC_LOG_DIR": "logs"},
			check: func(t *testing.T, c *Config) {
				if !filepath.IsAbs(c.LogDir) || filepath.Base(c.LogDir) != "logs" {
					t.Errorf("LogDir = %q", c.LogDir)
				}
			}},
		{name: "log retention", env: map[string]string{"PIHOLE_RBAC_LOG_RETENTION_DAYS": "14"},
			check: func(t *testing.T, c *Config) {
				if c.LogRetentionDays != 14 {
					t.Errorf("LogRetentionDays = %d", c.LogRetentionDays)
				}
			}},
		{name: "log retention 0 keeps everything", env: map[string]string{"PIHOLE_RBAC_LOG_RETENTION_DAYS": "0"},
			check: func(t *testing.T, c *Config) {
				if c.LogRetentionDays != 0 {
					t.Errorf("LogRetentionDays = %d", c.LogRetentionDays)
				}
			}},
		{name: "log retention negative", env: map[string]string{"PIHOLE_RBAC_LOG_RETENTION_DAYS": "-1"}, wantErr: "PIHOLE_RBAC_LOG_RETENTION_DAYS"},
		{name: "log retention too long", env: map[string]string{"PIHOLE_RBAC_LOG_RETENTION_DAYS": "3651"}, wantErr: "PIHOLE_RBAC_LOG_RETENTION_DAYS"},
		{name: "log retention not a number", env: map[string]string{"PIHOLE_RBAC_LOG_RETENTION_DAYS": "30d"}, wantErr: "PIHOLE_RBAC_LOG_RETENTION_DAYS"},
		{name: "ldap ca file", env: map[string]string{"PIHOLE_RBAC_LDAP_CA_FILE": "/etc/ssl/internal.pem"},
			check: func(t *testing.T, c *Config) {
				if c.LDAPCAFile != "/etc/ssl/internal.pem" {
					t.Errorf("LDAPCAFile = %q", c.LDAPCAFile)
				}
			}},
		{name: "trusted proxies", env: map[string]string{"PIHOLE_RBAC_TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.5 fd00::/8,::1"},
			check: func(t *testing.T, c *Config) {
				want := []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.1.5/32"),
					netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("::1/128"),
				}
				if !slices.Equal(c.TrustedProxies, want) {
					t.Errorf("TrustedProxies = %v", c.TrustedProxies)
				}
			}},
		{name: "trusted proxy host bits masked", env: map[string]string{"PIHOLE_RBAC_TRUSTED_PROXIES": "172.16.5.4/12"},
			check: func(t *testing.T, c *Config) {
				if c.TrustedProxies[0] != netip.MustParsePrefix("172.16.0.0/12") {
					t.Errorf("TrustedProxies = %v", c.TrustedProxies)
				}
			}},
		{name: "trusted proxies invalid", env: map[string]string{"PIHOLE_RBAC_TRUSTED_PROXIES": "10.0.0.0/8,proxy.lan"}, wantErr: "PIHOLE_RBAC_TRUSTED_PROXIES"},
		{name: "trusted proxies mapped v4", env: map[string]string{"PIHOLE_RBAC_TRUSTED_PROXIES": "::ffff:10.0.0.0/104"}, wantErr: "IPv4 form"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Load(env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoadReportsEveryError(t *testing.T) {
	_, err := Load(env(map[string]string{
		"PIHOLE_RBAC_LOG_LEVEL":     "loud",
		"PIHOLE_RBAC_COOKIE_SECURE": "maybe",
	}))
	if err == nil || !strings.Contains(err.Error(), "LOG_LEVEL") || !strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("err = %v, want both variables reported", err)
	}
}

func TestIsTrustedProxy(t *testing.T) {
	c, err := Load(env(map[string]string{"PIHOLE_RBAC_TRUSTED_PROXIES": "10.1.0.0/16,::1"}))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3", true},
		{"::ffff:10.1.2.3", true}, // IPv4-mapped, as a dual-stack listener reports it
		{"10.2.0.1", false},
		{"::1", true},
		{"127.0.0.1", false},
	}
	for _, tt := range tests {
		if got := c.IsTrustedProxy(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("IsTrustedProxy(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}
