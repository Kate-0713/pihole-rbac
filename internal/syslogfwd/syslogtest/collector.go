// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syslogtest is a fake syslog collector for tests: it listens on TCP, TLS (with certificates made for the
// test) or UDP, decodes what arrives and keeps the messages, and can be stopped, restarted on the same port, or made
// to drop its connections, so the forwarder's behaviour with a collector that goes away can be tested.
package syslogtest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Collector is a running fake collector.
type Collector struct {
	Host   string
	Port   int
	CAFile string // for TLS: the PEM file of the CA that signed the collector's certificate

	t       testing.TB
	network string // "tcp" or "udp"
	tlsCfg  *tls.Config

	mu    sync.Mutex
	ln    net.Listener
	pc    net.PacketConn
	conns map[net.Conn]struct{}
	msgs  []string
	wg    sync.WaitGroup
}

// NewTCP starts a plain TCP collector on a free local port.
func NewTCP(t testing.TB) *Collector { return start(t, "tcp", nil, "") }

// NewUDP starts a UDP collector on a free local port.
func NewUDP(t testing.TB) *Collector { return start(t, "udp", nil, "") }

// NewTLS starts a TLS collector whose certificate (for 127.0.0.1 and localhost) is signed by a CA made for the test.
// CAFile holds that CA, so a destination set to verify trusts it.
func NewTLS(t testing.TB) *Collector {
	cfg, ca := certs(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	return start(t, "tcp", cfg, path)
}

func start(t testing.TB, network string, cfg *tls.Config, caFile string) *Collector {
	c := &Collector{Host: "127.0.0.1", t: t, network: network, tlsCfg: cfg, CAFile: caFile, conns: map[net.Conn]struct{}{}}
	c.listen("127.0.0.1:0")
	t.Cleanup(c.Stop)
	return c
}

func (c *Collector) listen(addr string) {
	c.t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.network == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			c.t.Fatal(err)
		}
		c.pc = pc
		c.Port = pc.LocalAddr().(*net.UDPAddr).Port
		c.wg.Add(1)
		go c.serveUDP(pc)
		return
	}
	var ln net.Listener
	var err error
	for range 50 { // the port may take a moment to come free after Stop
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		c.t.Fatal(err)
	}
	if c.tlsCfg != nil {
		ln = tls.NewListener(ln, c.tlsCfg)
	}
	c.ln = ln
	c.Port = ln.Addr().(*net.TCPAddr).Port
	c.wg.Add(1)
	go c.serveTCP(ln)
}

func (c *Collector) serveTCP(ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.conns[conn] = struct{}{}
		c.mu.Unlock()
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				msg, err := readFrame(r)
				if err != nil {
					return
				}
				c.mu.Lock()
				c.msgs = append(c.msgs, msg)
				c.mu.Unlock()
			}
		}()
	}
}

func (c *Collector) serveUDP(pc net.PacketConn) {
	defer c.wg.Done()
	buf := make([]byte, 70000)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		c.mu.Lock()
		c.msgs = append(c.msgs, string(buf[:n]))
		c.mu.Unlock()
	}
}

// readFrame reads one octet-counted message: its length in decimal, a space, then that many bytes.
func readFrame(r *bufio.Reader) (string, error) {
	var n int
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == ' ' {
			break
		}
		if b < '0' || b > '9' {
			return "", fmt.Errorf("syslogtest: %q in a frame length", b)
		}
		n = n*10 + int(b-'0')
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// Messages returns what has arrived, in order.
func (c *Collector) Messages() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

// Wait waits until at least n messages have arrived, and returns all of them. It fails the test after timeout.
func (c *Collector) Wait(n int, timeout time.Duration) []string {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if m := c.Messages(); len(m) >= n {
			return m
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("syslogtest: %d messages after %s, want %d: %q", len(c.Messages()), timeout, n, c.Messages())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// DropConnections closes every open connection from the collector's side and keeps listening, as a collector that
// restarted or timed an idle connection out does.
func (c *Collector) DropConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.conns = map[net.Conn]struct{}{}
}

// Stop stops listening and closes connections. Messages already received are kept.
func (c *Collector) Stop() {
	c.mu.Lock()
	if c.ln != nil {
		_ = c.ln.Close()
		c.ln = nil
	}
	if c.pc != nil {
		_ = c.pc.Close()
		c.pc = nil
	}
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.conns = map[net.Conn]struct{}{}
	c.mu.Unlock()
	c.wg.Wait()
}

// Restart listens again on the same port.
func (c *Collector) Restart() { c.listen(net.JoinHostPort(c.Host, strconv.Itoa(c.Port))) }

// certs makes a CA and a server certificate for 127.0.0.1 and localhost signed by it.
func certs(t testing.TB) (*tls.Config, []byte) {
	cfg, ca, _, _ := makeCerts(t)
	return cfg, ca
}

// WriteCerts writes a CA, and a server certificate and key signed by it (for 127.0.0.1 and localhost), as PEM files
// in dir, for a real collector to be started with.
func WriteCerts(t testing.TB, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	_, ca, cert, key := makeCerts(t)
	write := func(name string, b []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return write("ca.pem", ca), write("server.pem", cert), write("server.key", key)
}

func makeCerts(t testing.TB) (cfg *tls.Config, caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "syslogtest CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
