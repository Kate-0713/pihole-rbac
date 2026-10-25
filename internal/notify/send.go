// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// Kind is a channel's kind.
type Kind string

const (
	Discord Kind = "discord"
	Matrix  Kind = "matrix"
)

// Destination is where one channel's messages go, with its secret: a Discord webhook URL, or a Matrix homeserver,
// room and access token. It is built from a channel row and its decrypted (or environment) secret, and is never
// stored or logged; the secret prints as [redacted].
type Destination struct {
	ChannelID int64
	Name      string // the channel's name, for logs and messages
	Kind      Kind
	Secret    secrets.Value // Discord: the webhook URL; Matrix: the access token
	Matrix    MatrixConfig  // Matrix only
}

// Result is how one attempt to send went. It never holds a response body: a homeserver may be internal, and its
// answer must not reach the person sending a test.
type Result struct {
	Status     int           // HTTP status, or 0 when there was no answer
	Errcode    string        // Matrix's errcode (M_FORBIDDEN, say), when it sent one
	RetryAfter time.Duration // from a 429, capped
	Err        error         // nil when the message was accepted
}

// OK reports whether the destination accepted the message.
func (r Result) OK() bool { return r.Err == nil }

// Retryable reports whether trying again later could work: no answer, a rate limit, or a server error. A refusal
// (a deleted webhook, a bad token) won't fix itself.
func (r Result) Retryable() bool {
	return r.Err != nil && (r.Status == 0 || r.Status == http.StatusTooManyRequests || r.Status >= 500)
}

const (
	sendTimeout   = 10 * time.Second
	maxResponse   = 4 << 10 // bytes of a response read, to find Matrix's errcode
	maxRetryAfter = time.Minute
)

// NewHTTPClient is the client notifications are sent with: a 10-second timeout, TLS 1.2 or later, the environment's
// proxy settings (Discord is on the internet, and a locked-down host may only reach it through a proxy), and no
// redirects, so a destination can't bounce the request (or a Matrix token) somewhere else.
func NewHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return noRedirects(&http.Client{Transport: t, Timeout: sendTimeout})
}

func noRedirects(c *http.Client) *http.Client {
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// Sender sends one message to one destination. It is safe for concurrent use.
type Sender struct {
	Client *http.Client // NewHTTPClient by default; its redirect policy is always replaced with none

	once sync.Once
}

func (s *Sender) client() *http.Client {
	s.once.Do(func() {
		if s.Client == nil {
			s.Client = NewHTTPClient()
		} else {
			noRedirects(s.Client)
		}
	})
	return s.Client
}

// Send makes one attempt. The destination is checked again first, so a row changed behind the app's back still can't
// send anywhere the rules don't allow.
func (s *Sender) Send(ctx context.Context, d Destination, m *Message) Result {
	switch d.Kind {
	case Discord:
		return s.discord(ctx, d, m)
	case Matrix:
		return s.matrix(ctx, d, m)
	}
	return Result{Err: fmt.Errorf("unknown channel kind %q", d.Kind)}
}

func (s *Sender) discord(ctx context.Context, d Destination, m *Message) Result {
	endpoint, _, err := ParseDiscordWebhook(d.Secret.Reveal())
	if err != nil {
		return Result{Err: errors.New("the stored webhook URL isn't a valid Discord webhook")}
	}
	body, err := json.Marshal(map[string]any{
		"content": m.Discord(),
		// No @everyone, @here, role or user pings, whatever the message says.
		"allowed_mentions": map[string]any{"parse": []string{}},
	})
	if err != nil {
		return Result{Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Err: errors.New("building the request failed")}
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req)
}

func (s *Sender) matrix(ctx context.Context, d Destination, m *Message) Result {
	cfg, err := d.Matrix.Normalize()
	if err != nil {
		return Result{Err: fmt.Errorf("the channel's Matrix settings aren't valid: %w", err)}
	}
	token := d.Secret.Reveal()
	if err := CheckMatrixToken(token); err != nil {
		return Result{Err: errors.New("the stored access token isn't valid")}
	}
	txn := make([]byte, 16)
	if _, err := rand.Read(txn); err != nil {
		return Result{Err: err}
	}
	endpoint := cfg.Homeserver + "/_matrix/client/v3/rooms/" + url.PathEscape(cfg.RoomID) +
		"/send/m.room.message/" + hex.EncodeToString(txn)
	body, err := json.Marshal(map[string]string{
		"msgtype":        "m.text",
		"body":           m.Plain(),
		"format":         "org.matrix.custom.html",
		"formatted_body": m.HTML(),
	})
	if err != nil {
		return Result{Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Err: errors.New("building the request failed")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return s.do(req)
}

var errcodePattern = regexp.MustCompile(`^M_[A-Z_]{1,64}$`)

func (s *Sender) do(req *http.Request) Result {
	res, err := s.client().Do(req)
	if err != nil {
		// A *url.Error repeats the URL, and a Discord webhook URL holds its token: keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Result{Err: fmt.Errorf("no answer: %w", err)}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	r := Result{Status: res.StatusCode}
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return r
	}
	var mx struct {
		Errcode string `json:"errcode"`
	}
	if json.Unmarshal(raw, &mx) == nil && errcodePattern.MatchString(mx.Errcode) {
		r.Errcode = mx.Errcode
	}
	if res.StatusCode == http.StatusTooManyRequests {
		r.RetryAfter = retryAfter(res.Header.Get("Retry-After"))
	}
	switch {
	case res.StatusCode >= 300 && res.StatusCode < 400:
		r.Err = fmt.Errorf("answered with a redirect (status %d), which isn't followed", res.StatusCode)
	case r.Errcode != "":
		r.Err = fmt.Errorf("refused with status %d (%s)", res.StatusCode, r.Errcode)
	default:
		r.Err = fmt.Errorf("refused with status %d", res.StatusCode)
	}
	return r
}

// retryAfter reads a Retry-After header in seconds (Discord sends them, sometimes with a fraction), capped.
func retryAfter(h string) time.Duration {
	f, err := strconv.ParseFloat(h, 64)
	if err != nil || f <= 0 {
		return 0
	}
	d := time.Duration(f * float64(time.Second))
	return min(d, maxRetryAfter)
}
