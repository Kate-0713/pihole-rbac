// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

func TestConfigValidate(t *testing.T) {
	ok := Config{Host: "graylog.lab", Port: 6514, Transport: TransportTLS, TLSMode: TLSVerify}
	for name, tc := range map[string]struct {
		mod  func(*Config)
		fail bool
	}{
		"as is":                   {func(*Config) {}, false},
		"an IPv4 address":         {func(c *Config) { c.Host = "10.0.0.9" }, false},
		"an IPv6 address":         {func(c *Config) { c.Host = "fd00::9" }, false},
		"a short name":            {func(c *Config) { c.Host = "graylog" }, false},
		"an underscore":           {func(c *Config) { c.Host = "log_host.lab" }, false},
		"plain tcp":               {func(c *Config) { c.Transport, c.Port = TransportTCP, 514 }, false},
		"udp":                     {func(c *Config) { c.Transport, c.Port = TransportUDP, 514 }, false},
		"an empty TLS mode":       {func(c *Config) { c.TLSMode = "" }, false},
		"insecure":                {func(c *Config) { c.TLSMode = TLSInsecure }, false},
		"a CA file with verify":   {func(c *Config) { c.CAFile = "/etc/ca.pem" }, false},
		"an empty host":           {func(c *Config) { c.Host = "" }, true},
		"a scheme":                {func(c *Config) { c.Host = "https://graylog.lab" }, true},
		"a port in the host":      {func(c *Config) { c.Host = "graylog.lab:6514" }, true},
		"a space":                 {func(c *Config) { c.Host = "gray log" }, true},
		"a newline":               {func(c *Config) { c.Host = "graylog.lab\nx" }, true},
		"an empty label":          {func(c *Config) { c.Host = "graylog..lab" }, true},
		"a hyphen first":          {func(c *Config) { c.Host = "-graylog.lab" }, true},
		"a path":                  {func(c *Config) { c.Host = "graylog.lab/x" }, true},
		"a host over 253":         {func(c *Config) { c.Host = strings.Repeat("a.", 130) + "b" }, true},
		"a label over 63":         {func(c *Config) { c.Host = strings.Repeat("a", 64) + ".lab" }, true},
		"port 0":                  {func(c *Config) { c.Port = 0 }, true},
		"port 65536":              {func(c *Config) { c.Port = 65536 }, true},
		"an unknown transport":    {func(c *Config) { c.Transport = "http" }, true},
		"an unknown TLS mode":     {func(c *Config) { c.TLSMode = "skip" }, true},
		"a CA file with insecure": {func(c *Config) { c.TLSMode, c.CAFile = TLSInsecure, "/ca.pem" }, true},
		"a CA file without TLS":   {func(c *Config) { c.Transport, c.CAFile = TransportTCP, "/ca.pem" }, true},
	} {
		t.Run(name, func(t *testing.T) {
			c := ok
			tc.mod(&c)
			if err := c.Validate(); (err != nil) != tc.fail {
				t.Errorf("Validate: %v, want failure %v", err, tc.fail)
			}
		})
	}
}

func cfgFor(c *syslogtest.Collector, transport string) Config {
	return Config{Host: c.Host, Port: c.Port, Transport: transport, TLSMode: TLSVerify, CAFile: c.CAFile}
}

func send(t *testing.T, w *Writer, msgs ...string) error {
	t.Helper()
	b := make([][]byte, len(msgs))
	for i, m := range msgs {
		b[i] = []byte(m)
	}
	return w.Write(context.Background(), b)
}

func TestWriterTCPFramesAndOrder(t *testing.T) {
	c := syslogtest.NewTCP(t)
	w := NewWriter(cfgFor(c, TransportTCP))
	defer w.Close()
	// A message may hold a newline or spaces: octet counting doesn't care.
	if err := send(t, w, "one", "two words", "three\nlines"); err != nil {
		t.Fatal(err)
	}
	if err := send(t, w, "four"); err != nil {
		t.Fatal(err)
	}
	got := c.Wait(4, 2*time.Second)
	if strings.Join(got, "|") != "one|two words|three\nlines|four" {
		t.Errorf("got %q", got)
	}
}

func TestWriterTLS(t *testing.T) {
	c := syslogtest.NewTLS(t)
	t.Run("verify with the CA file", func(t *testing.T) {
		w := NewWriter(cfgFor(c, TransportTLS))
		defer w.Close()
		if err := send(t, w, "secure"); err != nil {
			t.Fatal(err)
		}
		c.Wait(1, 2*time.Second)
	})
	t.Run("verify without the CA file", func(t *testing.T) {
		cfg := cfgFor(c, TransportTLS)
		cfg.CAFile = ""
		w := NewWriter(cfg)
		defer w.Close()
		err := send(t, w, "refused")
		if CodeOf(err) != CodeTLS {
			t.Errorf("code %q (%v), want %s", CodeOf(err), err, CodeTLS)
		}
	})
	t.Run("insecure", func(t *testing.T) {
		cfg := cfgFor(c, TransportTLS)
		cfg.TLSMode, cfg.CAFile = TLSInsecure, ""
		w := NewWriter(cfg)
		defer w.Close()
		if err := send(t, w, "unchecked"); err != nil {
			t.Fatal(err)
		}
		c.Wait(2, 2*time.Second)
	})
	t.Run("a name the certificate isn't for", func(t *testing.T) {
		cfg := cfgFor(c, TransportTLS)
		cfg.Host = "localhost" // the certificate names it, and it resolves to 127.0.0.1
		w := NewWriter(cfg)
		defer w.Close()
		if err := send(t, w, "by name"); err != nil {
			t.Fatalf("a name on the certificate: %v", err)
		}
	})
	t.Run("plain text to a TLS port", func(t *testing.T) {
		cfg := cfgFor(c, TransportTCP)
		cfg.CAFile = ""
		w := NewWriter(cfg)
		defer w.Close()
		// The collector tries a handshake on what is sent and closes. The write itself may succeed.
		_ = send(t, w, "hello")
	})
}

func TestWriterUDP(t *testing.T) {
	c := syslogtest.NewUDP(t)
	w := NewWriter(cfgFor(c, TransportUDP))
	defer w.Close()
	if err := send(t, w, "first", "second"); err != nil {
		t.Fatal(err)
	}
	got := c.Wait(2, 2*time.Second)
	if got[0] != "first" || got[1] != "second" {
		t.Errorf("datagrams %q: UDP carries each message as it is, unframed", got)
	}
}

// A collector that closed the connection between batches would swallow the next write. The writer finds the close
// first and dials again.
func TestWriterRedialsAfterTheCollectorClosed(t *testing.T) {
	for _, mk := range []struct {
		name      string
		start     func(testing.TB) *syslogtest.Collector
		transport string
	}{{"tcp", syslogtest.NewTCP, TransportTCP}, {"tls", syslogtest.NewTLS, TransportTLS}} {
		t.Run(mk.name, func(t *testing.T) {
			c := mk.start(t)
			w := NewWriter(cfgFor(c, mk.transport))
			defer w.Close()
			if err := send(t, w, "before"); err != nil {
				t.Fatal(err)
			}
			c.Wait(1, 2*time.Second)
			c.DropConnections()
			time.Sleep(50 * time.Millisecond)
			if err := send(t, w, "after"); err != nil {
				t.Fatalf("after the collector closed: %v", err)
			}
			got := c.Wait(2, 2*time.Second)
			if got[0] != "before" || got[1] != "after" {
				t.Errorf("got %q", got)
			}
		})
	}
}

func TestWriterCodes(t *testing.T) {
	// A port nothing listens on.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	w := NewWriter(Config{Host: "127.0.0.1", Port: port, Transport: TransportTCP})
	if err := send(t, w, "x"); CodeOf(err) != CodeDial {
		t.Errorf("a closed port: %q (%v), want %s", CodeOf(err), err, CodeDial)
	}

	// A CA file that isn't there, and one with no certificates in it.
	cfg := Config{Host: "127.0.0.1", Port: 6514, Transport: TransportTLS, TLSMode: TLSVerify, CAFile: filepath.Join(t.TempDir(), "missing.pem")}
	if err := send(t, NewWriter(cfg), "x"); CodeOf(err) != CodeCAFile {
		t.Errorf("a missing CA file: %q, want %s", CodeOf(err), CodeCAFile)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = bad
	if err := send(t, NewWriter(cfg), "x"); CodeOf(err) != CodeCAFile {
		t.Errorf("a CA file with no certificates: %q, want %s", CodeOf(err), CodeCAFile)
	}

	// Settings that don't validate are refused before anything is dialled.
	if err := send(t, NewWriter(Config{Host: "a b", Port: 1, Transport: TransportTCP}), "x"); CodeOf(err) != CodeConfig {
		t.Errorf("an invalid host: %q, want %s", CodeOf(err), CodeConfig)
	}

	// A collector that accepts and never completes the handshake times out.
	hang, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hang.Close()
	go func() {
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	tw := NewWriter(Config{Host: "127.0.0.1", Port: hang.Addr().(*net.TCPAddr).Port, Transport: TransportTLS, TLSMode: TLSInsecure})
	tw.Timeout = 100 * time.Millisecond
	if err := send(t, tw, "x"); CodeOf(err) != CodeTimeout {
		t.Errorf("a handshake that never ends: %q (%v), want %s", CodeOf(err), err, CodeTimeout)
	}
}

// What the error says is for logs only: its code is all a page or audit row shows.
func TestCodeOf(t *testing.T) {
	if CodeOf(nil) != "failed" || CodeOf(os.ErrNotExist) != "failed" || CodeOf(&Error{CodeDial, os.ErrNotExist}) != CodeDial {
		t.Error("CodeOf")
	}
}

func TestTest(t *testing.T) {
	c := syslogtest.NewTLS(t)
	if err := Test(context.Background(), cfgFor(c, TransportTLS), "host1"); err != nil {
		t.Fatal(err)
	}
	p := split(t, []byte(c.Wait(1, 2*time.Second)[0]))
	if p.msgid != "test" || p.host != "host1" {
		t.Errorf("%+v", p)
	}
	c.Stop()
	if err := Test(context.Background(), cfgFor(c, TransportTLS), "host1"); CodeOf(err) != CodeDial {
		t.Errorf("a stopped collector: %q, want %s", CodeOf(err), CodeDial)
	}
}
