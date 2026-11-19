// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Transports and TLS modes, as stored in log_destinations.
const (
	TransportTLS = "tls"
	TransportTCP = "tcp"
	TransportUDP = "udp"

	TLSVerify   = "verify"
	TLSInsecure = "insecure" // lab use only: the collector's certificate isn't checked at all
)

// Config says where and how to send.
type Config struct {
	Host      string
	Port      int
	Transport string // TransportTLS, TransportTCP or TransportUDP
	TLSMode   string // TLSVerify (the default) or TLSInsecure; only for TLS
	CAFile    string // extra trusted CAs (PEM), only with TLS and TLSVerify
}

// Plain reports whether the transport sends the audit log unencrypted.
func (c Config) Plain() bool { return c.Transport == TransportTCP || c.Transport == TransportUDP }

// Limit is the largest message the transport carries.
func (c Config) Limit() int {
	if c.Transport == TransportUDP {
		return UDPLimit
	}
	return StreamLimit
}

// ConfigError is a setting that isn't valid, with the API field it belongs to.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string { return e.Message }

// Validate checks the settings before anything is dialled. The host is a name or an address, with no scheme, port,
// whitespace or control characters. A refusal is a *ConfigError.
func (c Config) Validate() error {
	if msg := validHost(c.Host); msg != "" {
		return &ConfigError{"host", msg}
	}
	if c.Port < 1 || c.Port > 65535 {
		return &ConfigError{"port", "The port is from 1 to 65535."}
	}
	switch c.Transport {
	case TransportTLS, TransportTCP, TransportUDP:
	default:
		return &ConfigError{"transport", fmt.Sprintf("The transport is %q, %q or %q.", TransportTLS, TransportTCP, TransportUDP)}
	}
	switch c.TLSMode {
	case "", TLSVerify, TLSInsecure:
	default:
		return &ConfigError{"tls_mode", fmt.Sprintf("The TLS mode is %q or %q.", TLSVerify, TLSInsecure)}
	}
	if c.CAFile != "" && (c.Transport != TransportTLS || c.TLSMode == TLSInsecure) {
		return &ConfigError{"ca_file", "A CA file only works with TLS and certificate checking."}
	}
	return nil
}

// validHost returns why h isn't a host name or address, or "" if it is.
func validHost(h string) string {
	const bad = "The host is a name or an address, with no scheme, port or spaces."
	if h == "" || len(h) > 253 {
		return "The host is 1 to 253 characters."
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return bad
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return bad
			}
		}
	}
	return ""
}

// Codes of a send that failed. They are all a destination's page and the audit log ever say: what the far end
// answered, or what an error from the network library says, can name internal addresses.
const (
	CodeConfig  = "invalid_config"
	CodeCAFile  = "ca_file_invalid"
	CodeDial    = "dial_failed"
	CodeTLS     = "tls_failed"
	CodeTimeout = "timeout"
	CodeWrite   = "write_failed"
)

// Error is a failed send, with a short code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns an error's code, or "failed" for one that has none.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return "failed"
}

const defaultTimeout = 10 * time.Second

// Writer sends messages to one collector over one connection, dialled when needed and kept open between batches. It
// is safe for concurrent use, one batch at a time.
type Writer struct {
	Config  Config
	Timeout time.Duration // dialling and each write; 10 seconds if zero

	mu   sync.Mutex
	conn net.Conn
}

// NewWriter returns a Writer for c. Nothing is dialled until the first Write.
func NewWriter(c Config) *Writer { return &Writer{Config: c} }

func (w *Writer) timeout() time.Duration {
	if w.Timeout > 0 {
		return w.Timeout
	}
	return defaultTimeout
}

// Write sends msgs in order, framed for a stream or one datagram each. It returns once they are written, which over
// TCP or UDP says nothing about whether the collector got them. After an error the connection is dropped, and the next
// Write dials again, so the caller sends the whole batch again.
func (w *Writer) Write(ctx context.Context, msgs [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.Config.Validate(); err != nil {
		return &Error{CodeConfig, err}
	}
	if w.conn != nil && w.Config.Transport != TransportUDP && !alive(w.conn) {
		w.drop() // the collector closed it between batches: dial again rather than write into a dead connection
	}
	if w.conn == nil {
		c, err := w.dial(ctx)
		if err != nil {
			return err
		}
		w.conn = c
	}
	var err error
	if w.Config.Transport == TransportUDP {
		for _, m := range msgs {
			if err = w.write(m); err != nil {
				break
			}
		}
	} else {
		var buf []byte
		for _, m := range msgs {
			buf = append(buf, Frame(m)...)
		}
		err = w.write(buf)
	}
	if err != nil {
		w.drop()
		return err
	}
	return nil
}

func (w *Writer) write(b []byte) error {
	_ = w.conn.SetWriteDeadline(time.Now().Add(w.timeout()))
	if _, err := w.conn.Write(b); err != nil {
		return &Error{codeOf(err, CodeWrite), err}
	}
	return nil
}

func (w *Writer) drop() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// Close closes the connection. The Writer can be used again.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.drop()
	return nil
}

func codeOf(err error, otherwise string) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CodeTimeout
	}
	return otherwise
}

func (w *Writer) dial(ctx context.Context) (net.Conn, error) {
	cfg := w.Config
	network := "tcp"
	if cfg.Transport == TransportUDP {
		network = "udp"
	}
	tlsCfg, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: w.timeout()}
	c, err := d.DialContext(ctx, network, net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, &Error{codeOf(err, CodeDial), err}
	}
	if tlsCfg == nil {
		return c, nil
	}
	tc := tls.Client(c, tlsCfg)
	hctx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = c.Close()
		return nil, &Error{codeOf(err, CodeTLS), err}
	}
	return tc, nil
}

// tlsConfig is nil unless the transport is TLS. The CA file is read at each dial, so a replaced bundle is picked up.
func (c Config) tlsConfig() (*tls.Config, error) {
	if c.Transport != TransportTLS {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.Host}
	if c.TLSMode == TLSInsecure {
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicit, documented lab-only setting
		return cfg, nil
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, &Error{CodeCAFile, err}
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &Error{CodeCAFile, errors.New("no certificates in the CA file")}
		}
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// alive reports whether a stream connection is still open at the far end. A collector that closed it has sent a FIN,
// which a read finds at once, where a write would succeed and the message be lost. A read that simply times out
// means nothing has arrived and the connection is open.
func alive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	defer c.SetReadDeadline(time.Time{}) //nolint:errcheck
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		return true // a collector that talks back isn't closed; the byte is discarded
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Test connects, sends one test message and closes, for a destination's Test button. The result is a code, never
// anything from the far end.
func Test(ctx context.Context, c Config, hostname string) error {
	w := NewWriter(c)
	defer w.Close()
	return w.Write(ctx, [][]byte{FormatTest(time.Now(), hostname)})
}
