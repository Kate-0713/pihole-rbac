// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

// These tests send to a real rsyslog, to check what the fake collector can't: that a real receiver parses the
// messages (RFC 5424, octet counting over TCP and TLS, one datagram over UDP). They only run when
// PIHOLE_RBAC_TEST_RSYSLOG is set, with rsyslogd (and for TLS, its gnutls module) installed: CI sets it. By
// default rsyslogd is found on the path; PIHOLE_RBAC_RSYSLOGD names another, which CI uses because the distribution's
// AppArmor profile stops rsyslogd reading files outside its own directories.
//
// rsyslog writes each message as: pri|version|timestamp|hostname|app-name|msgid|structured-data|msg

// A message as rsyslog parsed it.
type parsed struct {
	pri, version, timestamp, hostname, app, msgid, sd, msg string
}

func parseLine(t *testing.T, line string) parsed {
	t.Helper()
	f := strings.SplitN(line, "|", 8)
	if len(f) != 8 {
		t.Fatalf("not a parsed message: %q", line)
	}
	return parsed{f[0], f[1], f[2], f[3], f[4], f[5], f[6], strings.TrimPrefix(f[7], " ")}
}

type rsyslog struct {
	dir                   string
	tcpPort, udpPort, tls int
	tlsCA                 string
}

// freeTCP and freeUDP find a port that is free now. Another process could take it before rsyslog does, which is
// unlikely enough on a test machine.
func freeTCP(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDP(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

// startRsyslog runs rsyslogd with a listener each for plain TCP, UDP and, when withTLS, TLS. It skips the test
// unless PIHOLE_RBAC_TEST_RSYSLOG is set, and skips (or fails, on CI) a TLS test when rsyslog has no gtls module.
func startRsyslog(t *testing.T, withTLS bool) *rsyslog {
	t.Helper()
	if os.Getenv("PIHOLE_RBAC_TEST_RSYSLOG") == "" {
		t.Skip("set PIHOLE_RBAC_TEST_RSYSLOG=1 to test against a real rsyslog")
	}
	bin := os.Getenv("PIHOLE_RBAC_RSYSLOGD")
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("rsyslogd"); err != nil {
			t.Fatalf("PIHOLE_RBAC_TEST_RSYSLOG is set but rsyslogd isn't installed: %v", err)
		}
	}
	dir := t.TempDir()
	r := &rsyslog{dir: dir, tcpPort: freeTCP(t), udpPort: freeUDP(t)}
	var conf strings.Builder
	fmt.Fprintf(&conf, "global(workDirectory=%q maxMessageSize=\"256k\")\n", dir)
	if withTLS {
		ca, cert, key := syslogtest.WriteCerts(t, dir)
		r.tlsCA, r.tls = ca, freeTCP(t)
		fmt.Fprintf(&conf, "global(DefaultNetstreamDriver=\"gtls\" DefaultNetstreamDriverCAFile=%q DefaultNetstreamDriverCertFile=%q DefaultNetstreamDriverKeyFile=%q)\n", ca, cert, key)
	}
	conf.WriteString("module(load=\"imtcp\")\nmodule(load=\"imudp\")\n")
	conf.WriteString(`template(name="out" type="string" string="%pri%|%protocol-version%|%timestamp:::date-rfc3339%|%hostname%|%app-name%|%msgid%|%structured-data%|%msg%\n")` + "\n")
	for _, name := range []string{"tcp", "udp", "tls"} {
		fmt.Fprintf(&conf, "ruleset(name=%q) { action(type=\"omfile\" file=%q template=\"out\" flushOnTXEnd=\"on\" asyncWriting=\"off\" ioBufferSize=\"1k\") }\n",
			name, filepath.Join(dir, name+".log"))
	}
	fmt.Fprintf(&conf, "input(type=\"imtcp\" address=\"127.0.0.1\" port=\"%d\" ruleset=\"tcp\")\n", r.tcpPort)
	fmt.Fprintf(&conf, "input(type=\"imudp\" address=\"127.0.0.1\" port=\"%d\" ruleset=\"udp\")\n", r.udpPort)
	if withTLS {
		fmt.Fprintf(&conf, "input(type=\"imtcp\" address=\"127.0.0.1\" port=\"%d\" ruleset=\"tls\" streamDriver.name=\"gtls\" streamDriver.mode=\"1\" streamDriver.authMode=\"anon\")\n", r.tls)
	}
	confPath := filepath.Join(dir, "rsyslog.conf")
	if err := os.WriteFile(confPath, []byte(conf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-N1", "-f", confPath, "-i", filepath.Join(dir, "check.pid")).CombinedOutput(); err != nil {
		t.Fatalf("rsyslog rejected its configuration: %v\n%s", err, out)
	}
	var stderr bytes.Buffer
	cmd := exec.Command(bin, "-n", "-f", confPath, "-i", filepath.Join(dir, "rsyslog.pid"))
	cmd.Stdout, cmd.Stderr = io.Discard, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("rsyslog said: %s", stderr.String())
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", r.tcpPort), time.Second)
		if err == nil {
			c.Close()
			break
		}
		if withTLS && strings.Contains(stderr.String(), "lmnsd_gtls") && os.Getenv("CI") == "" {
			t.Skipf("this rsyslog has no gtls module (install rsyslog-gnutls): %s", stderr.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("rsyslog never listened: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return r
}

// lines waits until the file has n lines and returns them parsed.
func (r *rsyslog) lines(t *testing.T, name string, n int) []parsed {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(r.dir, name+".log"))
		got := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(b) > 0 && len(got) >= n {
			out := make([]parsed, 0, len(got))
			for _, l := range got {
				out = append(out, parseLine(t, l))
			}
			return out
		}
		if time.Now().After(deadline) {
			t.Fatalf("rsyslog's %s log has %d lines after 10 seconds, want %d:\n%s", name, len(got), n, b)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// entries are rows that stress the format: a failure, text a parser could trip on, and a detail near the stream limit.
func rsyslogEntries() []audit.Entry {
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	return []audit.Entry{
		{At: at, Username: "alice", Action: audit.ActionLogin, Target: "alice", IP: "10.0.0.5"},
		{At: at.Add(time.Second), Username: "mallory", Action: audit.ActionLogin, Target: "admin", IP: "10.0.0.9", Err: fmt.Errorf("wrong password")},
		{At: at.Add(2 * time.Second), Username: "bob", Action: audit.ActionDomainAdd, Target: "i-1",
			Detail: map[string]any{"domain": "päivää.example", "comment": "line one\nline two | pipe <tag> \"quoted\" 日本語"}},
		{At: at.Add(3 * time.Second), Username: "carol", Action: audit.ActionDomainAdd, Target: "i-1",
			Detail: map[string]any{"comment": strings.Repeat("x", 60<<10)}}, // under the stream limit, over rsyslog's default maximum
	}
}

func checkRsyslogEntries(t *testing.T, got []parsed, wantHost string) {
	t.Helper()
	if len(got) != 4 {
		t.Fatalf("%d messages, want 4", len(got))
	}
	for i, want := range []struct {
		pri, action, user string
	}{{"110", "login", "alice"}, {"108", "login", "mallory"}, {"110", "domain_add", "bob"}, {"110", "domain_add", "carol"}} {
		p := got[i]
		if p.pri != want.pri || p.version != "1" || p.hostname != wantHost || p.app != "pihole-rbac" || p.msgid != want.action || p.sd != "-" {
			t.Errorf("message %d header: %+v", i, p)
		}
		var j struct {
			ID     int64
			User   string
			Action string
			Result string
			Detail map[string]any
		}
		if err := json.Unmarshal([]byte(p.msg), &j); err != nil {
			t.Fatalf("message %d text isn't JSON (%d bytes): %v", i, len(p.msg), err)
		}
		if j.ID != int64(i+1) || j.User != want.user || j.Action != want.action {
			t.Errorf("message %d JSON: %+v", i, j)
		}
		if (i == 1) != (j.Result == audit.ResultFailure) {
			t.Errorf("message %d result %q", i, j.Result)
		}
	}
	if got[0].timestamp != "2026-11-18T12:00:00.000Z" {
		t.Errorf("timestamp %q", got[0].timestamp)
	}
	// The detail came through whole: the unicode, the newline and the pipe, and 60 KiB.
	var j struct{ Detail map[string]string }
	if err := json.Unmarshal([]byte(got[2].msg), &j); err != nil || j.Detail["comment"] != "line one\nline two | pipe <tag> \"quoted\" 日本語" || j.Detail["domain"] != "päivää.example" {
		t.Errorf("detail of message 2: %v %+v", err, j)
	}
	if err := json.Unmarshal([]byte(got[3].msg), &j); err != nil || len(j.Detail["comment"]) != 60<<10 {
		t.Errorf("detail of message 3: %v, %d bytes", err, len(j.Detail["comment"]))
	}
}

// forwardEntries sends rsyslogEntries through a real Forwarder over the real store, as the app does.
func forwardEntries(t *testing.T, cfg Config) {
	t.Helper()
	st := openStore(t)
	destID := makeDestination(t, st, 0)
	f := fast(&Forwarder{Dest: Destination{ID: destID, Name: "rsyslog", Config: cfg}, Store: DBStore{S: st}})
	f.Hostname = "rbac-host"
	run(t, f)
	for _, e := range rsyslogEntries() {
		insert(t, st, e)
	}
	f.Nudge()
	waitFor(t, "the forwarder to send every row", func() bool {
		cur, err := DBStore{S: st}.Cursor(context.Background(), destID)
		return err == nil && cur == int64(len(rsyslogEntries()))
	})
}

func TestRsyslogTCP(t *testing.T) {
	r := startRsyslog(t, false)
	forwardEntries(t, Config{Host: "127.0.0.1", Port: r.tcpPort, Transport: TransportTCP})
	checkRsyslogEntries(t, r.lines(t, "tcp", 4), "rbac-host")
}

func TestRsyslogTLS(t *testing.T) {
	r := startRsyslog(t, true)
	// Verified against the CA that signed rsyslog's certificate: the whole path a production destination uses.
	forwardEntries(t, Config{Host: "127.0.0.1", Port: r.tls, Transport: TransportTLS, TLSMode: TLSVerify, CAFile: r.tlsCA})
	checkRsyslogEntries(t, r.lines(t, "tls", 4), "rbac-host")

	// Without the CA, the certificate isn't trusted, and nothing is sent.
	w := NewWriter(Config{Host: "127.0.0.1", Port: r.tls, Transport: TransportTLS, TLSMode: TLSVerify})
	defer w.Close()
	if err := w.Write(context.Background(), [][]byte{FormatTest(time.Now(), "rbac-host")}); CodeOf(err) != CodeTLS {
		t.Errorf("an untrusted certificate: %v", err)
	}
	// insecure sends without checking, for a lab.
	if err := Test(context.Background(), Config{Host: "127.0.0.1", Port: r.tls, Transport: TransportTLS, TLSMode: TLSInsecure}, "rbac-host"); err != nil {
		t.Errorf("insecure: %v", err)
	}
	var found bool
	for _, p := range r.lines(t, "tls", 5) {
		found = found || p.msgid == "test"
	}
	if !found {
		t.Error("the test message didn't arrive over TLS")
	}
}

func TestRsyslogUDP(t *testing.T) {
	r := startRsyslog(t, false)
	cfg := Config{Host: "127.0.0.1", Port: r.udpPort, Transport: TransportUDP}
	w := NewWriter(cfg)
	defer w.Close()
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	small := Row{ID: 1, At: at, User: "alice", Action: "login", Target: "alice", Result: audit.ResultSuccess, Detail: `{"a":1}`, IP: "10.0.0.5"}
	big := Row{ID: 2, At: at, User: "bob", Action: "domain_add", Target: "i-1", Result: audit.ResultSuccess,
		Detail: fmt.Sprintf(`{"comment":%q}`, strings.Repeat("y", 5000)), IP: "10.0.0.5"}
	var msgs [][]byte
	for _, row := range []Row{small, big} {
		msgs = append(msgs, Format(row, "rbac-host", cfg.Limit()))
	}
	if err := w.Write(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	got := r.lines(t, "udp", 2)
	if got[0].msgid != "login" || got[0].pri != "110" || !strings.Contains(got[0].msg, `"detail":{"a":1}`) {
		t.Errorf("a small datagram: %+v", got[0])
	}
	// Over the UDP limit, the detail is replaced by a marker, so the datagram still fits.
	if got[1].msgid != "domain_add" || !strings.Contains(got[1].msg, `"detail":{"truncated":true}`) {
		t.Errorf("a large datagram: %.200s", got[1].msg)
	}
}
