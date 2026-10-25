// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

const (
	hookToken = "AbC-def_123ghiJKL"
	hookURL   = "https://discord.com/api/webhooks/123456789012345678/" + hookToken
)

func TestParseDiscordWebhook(t *testing.T) {
	good := map[string]string{
		hookURL: hookURL,
		"  https://DISCORD.com/api/webhooks/1/x  ":         "https://discord.com/api/webhooks/1/x",
		"https://discordapp.com/api/webhooks/42/tok":       "https://discordapp.com/api/webhooks/42/tok",
		"https://discord.com:443/api/webhooks/42/tok":      "https://discord.com/api/webhooks/42/tok",
		"https://discord.com/api/webhooks/42/tok-with_bit": "https://discord.com/api/webhooks/42/tok-with_bit",
	}
	for in, want := range good {
		got, id, err := ParseDiscordWebhook(in)
		if err != nil || got != want || id == "" {
			t.Errorf("%q: %q, %q, %v", in, got, id, err)
		}
	}
	for _, bad := range []string{
		"",
		"http://discord.com/api/webhooks/1/x",
		"https://discord.com.evil.example/api/webhooks/1/x",
		"https://evil.example/api/webhooks/1/x",
		"https://canary.discord.com/api/webhooks/1/x",
		"https://127.0.0.1/api/webhooks/1/x",
		"https://discord.com:8443/api/webhooks/1/x",
		"https://user:pw@discord.com/api/webhooks/1/x",
		"https://discord.com/api/webhooks/1/x?wait=true",
		"https://discord.com/api/webhooks/1/x#frag",
		"https://discord.com/api/webhooks/abc/x",
		"https://discord.com/api/webhooks/1",
		"https://discord.com/api/webhooks/1/x/extra",
		"https://discord.com/api/webhooks/1/x%2F..",
		"https://discord.com/api/v10/webhooks/1/x",
		"https://discord.com/api/webhooks/1/" + strings.Repeat("x", 101),
		"discord.com/api/webhooks/1/x",
		"https://discord.com/" + strings.Repeat("a", maxURL),
	} {
		_, _, err := ParseDiscordWebhook(bad)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "secret" {
			t.Errorf("%q: accepted or wrong error: %v", bad, err)
			continue
		}
		if strings.Contains(ve.Message, "/x") || strings.Contains(ve.Message, "evil") {
			t.Errorf("%q: the message repeats the URL: %s", bad, ve.Message)
		}
	}
}

func TestMatrixConfig(t *testing.T) {
	for _, tt := range []struct {
		in   MatrixConfig
		want string // the homeserver, or "" for refused
		bad  string // the field refused
	}{
		{MatrixConfig{Homeserver: "https://Matrix.Example.org/", RoomID: "!abc:example.org"}, "https://matrix.example.org", ""},
		{MatrixConfig{Homeserver: "https://10.0.0.5:8448/base/", RoomID: "!a-b_c.d=e/f+g:example.org:8448"}, "https://10.0.0.5:8448/base", ""},
		{MatrixConfig{Homeserver: "http://synapse.lan:8008", RoomID: "!x:lan", AllowHTTP: true}, "http://synapse.lan:8008", ""},
		{MatrixConfig{Homeserver: "http://synapse.lan:8008", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "ftp://example.org", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "https://u:p@example.org", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "https://example.org?x=1", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "https://example.org#x", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "https://example.org:http", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "", RoomID: "!x:lan"}, "", "homeserver"},
		{MatrixConfig{Homeserver: "https://example.org", RoomID: "#alias:example.org"}, "", "room_id"},
		{MatrixConfig{Homeserver: "https://example.org", RoomID: "!no-server"}, "", "room_id"},
		{MatrixConfig{Homeserver: "https://example.org", RoomID: "!a b:example.org"}, "", "room_id"},
	} {
		got, err := tt.in.Normalize()
		var ve *ValidationError
		switch {
		case tt.want != "" && (err != nil || got.Homeserver != tt.want):
			t.Errorf("%+v: %+v, %v", tt.in, got, err)
		case tt.want == "" && (!errors.As(err, &ve) || ve.Field != tt.bad):
			t.Errorf("%+v: want %s refused, got %v", tt.in, tt.bad, err)
		}
	}
	if CheckMatrixToken("syt_abc_123") != nil {
		t.Error("a normal token was refused")
	}
	for _, bad := range []string{"", "has space", "new\nline", "x\r\nX-Evil: 1", "nonasciié", strings.Repeat("t", maxToken+1)} {
		if CheckMatrixToken(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMessageRendering(t *testing.T) {
	m := (&Message{}).Bold("**mallory** @everyone").Text(" did *this*\nFAKE LINE <b>").Code("a`b")
	d := m.Discord()
	for _, unwanted := range []string{"\n", "**mallory**", " *this*", "`a`b`"} {
		if strings.Contains(d, unwanted) {
			t.Errorf("Discord rendering contains %q: %s", unwanted, d)
		}
	}
	if want := `**\*\*mallory\*\* \@everyone** did \*this\* FAKE LINE \<b\>` + "`a'b`"; d != want {
		t.Errorf("Discord:\n got %s\nwant %s", d, want)
	}
	if h := m.HTML(); h != `<strong>**mallory** @everyone</strong> did *this* FAKE LINE &lt;b&gt;<code>a`+"`"+`b</code>` {
		t.Errorf("HTML: %s", h)
	}
	if p := m.Plain(); p != "**mallory** @everyone did *this* FAKE LINE <b>a`b" {
		t.Errorf("Plain: %s", p)
	}

	long := &Message{}
	for range 20 {
		long.Text(strings.Repeat("y", 300))
	}
	if n := len([]rune(long.Discord())); n != maxDiscord {
		t.Errorf("a long message is %d characters", n)
	}
	if v := (&Message{}).Text(strings.Repeat("z", 500)).Plain(); len([]rune(v)) != maxValue || !strings.HasSuffix(v, "…") {
		t.Errorf("a long value isn't cut: %d", len([]rune(v)))
	}
}

func TestForEntry(t *testing.T) {
	ok := ForEntry(audit.Entry{
		Username: "alice", Action: audit.ActionDomainAdd, Target: "i-1", InstanceName: "pihole1",
		Detail: map[string]any{"domain": "ads.example.com", "comment": "long comment"},
	})
	if got := ok.Plain(); got != "alice domain add on i-1 (pihole1): ads.example.com — succeeded" {
		t.Errorf("success: %s", got)
	}
	failed := ForEntry(audit.Entry{
		Username: "alice", Action: audit.ActionBlockingSet, Target: "g-2", InstanceName: "pihole2",
		Err:    errors.New("dial tcp 10.0.0.7:443: connection refused"),
		Detail: map[string]any{"error_code": "pihole_unreachable"},
	})
	if got := failed.Plain(); got != "alice blocking set on g-2 (pihole2) — failed (pihole_unreachable)" {
		t.Errorf("Pi-hole failure: %s", got)
	}
	refused := ForEntry(audit.Entry{Username: "bob", Action: audit.ActionPermissionDenied,
		Err: &rbac.Error{Code: rbac.CodeForbidden, Message: "You can't."}})
	if got := refused.Plain(); !strings.HasSuffix(got, "failed (forbidden)") {
		t.Errorf("refusal: %s", got)
	}
	login := ForEntry(audit.Entry{Username: "mallory", Action: audit.ActionLogin, Err: errors.New("invalid username or password")})
	if got := login.Plain(); got != "mallory login — failed (error)" || strings.Contains(login.Discord(), "invalid") {
		t.Errorf("plain error: %s", got)
	}
}

func TestProtectedGroups(t *testing.T) {
	e := audit.Entry{Username: "alice", Action: audit.ActionClientUpdate, InstanceName: "pihole1",
		Detail: map[string]any{"client": "10.0.0.9", "protected_added": []string{"Kids", "Guests"}}}
	got := ProtectedGroups(e)
	if len(got) != 2 {
		t.Fatalf("groups %v", got)
	}
	if m := ForProtectedGroup(e, got).Plain(); m != "🚨 alice added client 10.0.0.9 to protected groups Kids, Guests on pihole1" {
		t.Errorf("alert: %s", m)
	}
	// As read back from JSON.
	var d map[string]any
	_ = json.Unmarshal([]byte(`{"protected_added":["Kids"]}`), &d)
	e.Detail = d
	if g := ProtectedGroups(e); len(g) != 1 || g[0] != "Kids" {
		t.Errorf("from JSON: %v", g)
	}
	e.Err = errors.New("failed")
	if ProtectedGroups(e) != nil {
		t.Error("a failed update raises an alert")
	}
	e.Err, e.Action = nil, audit.ActionDomainAdd
	if ProtectedGroups(e) != nil {
		t.Error("another action raises an alert")
	}
}

func TestProtectedAlerts(t *testing.T) {
	update := audit.Entry{Username: "alice", Action: audit.ActionClientUpdate, InstanceName: "pihole1",
		Detail: map[string]any{"client": "10.0.0.9", "protected_added": []string{"Kids"}}}
	if a := ProtectedAlerts(update); len(a) != 1 || a[0].Client != "10.0.0.9" || a[0].Groups[0] != "Kids" {
		t.Errorf("client_update: %+v", a)
	}

	// A client reset lists every client it put in a protected group; it alerts for each, even when other clients
	// failed.
	reset := audit.Entry{Username: audit.SystemUser, Action: audit.ActionClientReset, InstanceName: "pihole2",
		Err: errors.New("1 client reset, 1 failed"),
		Detail: map[string]any{"protected": []ProtectedClient{
			{Client: "10.0.0.1", Groups: []string{"Kids"}}, {Client: "10.0.0.2", Groups: []string{"Kids", "Guests"}}, {Client: "x"},
		}}}
	alerts := ProtectedAlerts(reset)
	if len(alerts) != 2 || alerts[1].Client != "10.0.0.2" || len(alerts[1].Groups) != 2 {
		t.Fatalf("client_reset: %+v", alerts)
	}
	if m := ForProtectedAlert(reset, alerts[0]).Plain(); m != "🚨 (system) added client 10.0.0.1 to protected group Kids on pihole2" {
		t.Errorf("alert: %s", m)
	}
	// As read back from JSON.
	var d map[string]any
	_ = json.Unmarshal([]byte(`{"protected":[{"client":"10.0.0.1","groups":["Kids"]},{"client":"bad","groups":"Kids"}]}`), &d)
	reset.Detail = d
	if a := ProtectedAlerts(reset); len(a) != 1 || a[0].Client != "10.0.0.1" || a[0].Groups[0] != "Kids" {
		t.Errorf("from JSON: %+v", a)
	}
	reset.Action = audit.ActionDomainAdd
	if ProtectedAlerts(reset) != nil {
		t.Error("another action raises an alert")
	}
}

// fake is an HTTPS server that every request is sent to, whatever its host, recording what arrived.
type fake struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []*http.Request
	bodies  []string
	respond func(w http.ResponseWriter, r *http.Request, n int) // n counts requests from 1
}

func newFake(t *testing.T, respond func(w http.ResponseWriter, r *http.Request, n int)) *fake {
	f := &fake{respond: respond}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, r)
		f.bodies = append(f.bodies, string(b))
		n := len(f.got)
		f.mu.Unlock()
		f.respond(w, r, n)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

// sender dials the fake for every host. The fake's certificate is for 127.0.0.1, so verification is off: only here.
func (f *fake) sender() *Sender {
	addr := f.srv.Listener.Addr().String()
	return &Sender{Client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}, Timeout: 5 * time.Second}}
}

func discordDest() Destination {
	return Destination{ChannelID: 1, Name: "ops", Kind: Discord, Secret: secrets.NewValue([]byte(hookURL))}
}

func matrixDest() Destination {
	return Destination{ChannelID: 2, Name: "room", Kind: Matrix, Secret: secrets.NewValue([]byte("syt_token_123")),
		Matrix: MatrixConfig{Homeserver: "https://matrix.example.org:8448", RoomID: "!room/id:example.org"}}
}

func TestSendDiscord(t *testing.T) {
	status := http.StatusNoContent
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "2.5")
		}
		if status == http.StatusFound {
			w.Header().Set("Location", "https://evil.example/collect")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message": "internal detail that must not leak"}`))
	})
	s := f.sender()
	msg := (&Message{}).Bold("alice").Text(" @everyone")

	r := s.Send(context.Background(), discordDest(), msg)
	if !r.OK() || r.Status != http.StatusNoContent {
		t.Fatalf("send: %+v", r)
	}
	req := f.got[0]
	if req.Method != http.MethodPost || req.Host != "discord.com" || req.URL.Path != "/api/webhooks/123456789012345678/"+hookToken ||
		req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request: %s %s%s", req.Method, req.Host, req.URL.Path)
	}
	var body struct {
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}
	if err := json.Unmarshal([]byte(f.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	if body.Content != `**alice** \@everyone` || body.AllowedMentions.Parse == nil || len(body.AllowedMentions.Parse) != 0 {
		t.Errorf("body: %s", f.bodies[0])
	}

	for _, tt := range []struct {
		status    int
		retryable bool
		after     time.Duration
	}{
		{http.StatusBadRequest, false, 0},
		{http.StatusNotFound, false, 0},
		{http.StatusTooManyRequests, true, 2500 * time.Millisecond},
		{http.StatusBadGateway, true, 0},
		{http.StatusFound, false, 0},
	} {
		status = tt.status
		before := f.count()
		r := s.Send(context.Background(), discordDest(), msg)
		if r.OK() || r.Status != tt.status || r.Retryable() != tt.retryable || r.RetryAfter != tt.after {
			t.Errorf("%d: %+v", tt.status, r)
		}
		if strings.Contains(r.Err.Error(), "internal detail") || strings.Contains(r.Err.Error(), hookToken) {
			t.Errorf("%d: the error leaks: %v", tt.status, r.Err)
		}
		if f.count() != before+1 {
			t.Errorf("%d: %d requests: a redirect was followed", tt.status, f.count()-before)
		}
	}

	// A destination the rules refuse is never contacted, even if the row says so.
	bad := discordDest()
	bad.Secret = secrets.NewValue([]byte("https://evil.example/api/webhooks/1/x"))
	before := f.count()
	if r := s.Send(context.Background(), bad, msg); r.OK() || f.count() != before {
		t.Errorf("an invalid webhook URL was sent to: %+v", r)
	}
}

func TestSendNoAnswer(t *testing.T) {
	// Nothing listens: the error is Retryable and doesn't repeat the URL, which holds the token.
	s := &Sender{Client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:1")
		},
	}}}
	r := s.Send(context.Background(), discordDest(), &Message{})
	if r.OK() || !r.Retryable() || r.Status != 0 || strings.Contains(r.Err.Error(), hookToken) {
		t.Errorf("%+v", r)
	}
}

func TestSendMatrix(t *testing.T) {
	status := http.StatusOK
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"errcode":"M_FORBIDDEN","error":"secret internal text"}`))
		}
	})
	s := f.sender()
	r := s.Send(context.Background(), matrixDest(), (&Message{}).Bold("<alice>").Text(" did it"))
	if !r.OK() {
		t.Fatalf("send: %+v", r)
	}
	req := f.got[0]
	if req.Method != http.MethodPut || req.Host != "matrix.example.org:8448" ||
		!strings.HasPrefix(req.URL.RawPath, "/_matrix/client/v3/rooms/%21room%2Fid:example.org/send/m.room.message/") ||
		req.Header.Get("Authorization") != "Bearer syt_token_123" {
		t.Errorf("request: %s %s %s %q", req.Method, req.Host, req.URL.RawPath, req.Header.Get("Authorization"))
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(f.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	if body["msgtype"] != "m.text" || body["body"] != "<alice> did it" ||
		body["formatted_body"] != "<strong>&lt;alice&gt;</strong> did it" || body["format"] != "org.matrix.custom.html" {
		t.Errorf("body: %v", body)
	}

	// Each message gets its own transaction ID.
	s.Send(context.Background(), matrixDest(), &Message{})
	if f.got[0].URL.Path == f.got[1].URL.Path {
		t.Error("transaction IDs repeat")
	}

	status = http.StatusForbidden
	r = s.Send(context.Background(), matrixDest(), &Message{})
	if r.OK() || r.Errcode != "M_FORBIDDEN" || r.Retryable() || strings.Contains(r.Err.Error(), "secret internal") ||
		strings.Contains(r.Err.Error(), "syt_token") {
		t.Errorf("refused: %+v", r)
	}

	// Plain HTTP needs allow_http, checked again at send time.
	d := matrixDest()
	d.Matrix.Homeserver = "http://matrix.example.org"
	before := f.count()
	if r := s.Send(context.Background(), d, &Message{}); r.OK() || f.count() != before {
		t.Errorf("plain HTTP without allow_http: %+v", r)
	}
}

// The notifier routes each entry to the channels that want it, retries what can be retried, and reports guards that
// gave up.
func TestNotifier(t *testing.T) {
	var mu sync.Mutex
	fails := map[string]int{} // path → failures still to give before succeeding
	f := newFake(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		mu.Lock()
		defer mu.Unlock()
		if fails[r.URL.Path] > 0 {
			fails[r.URL.Path]--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if strings.Contains(r.URL.Path, "/404/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	hook := func(id string) Destination {
		return Destination{Name: "hook-" + id, Kind: Discord, Secret: secrets.NewValue([]byte("https://discord.com/api/webhooks/" + id + "/tok"))}
	}
	var failedMu sync.Mutex
	var failed []string
	n := &Notifier{
		Sender: f.sender(), Delays: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond},
		Failed: func(j Job, r Result) { failedMu.Lock(); failed = append(failed, j.Destination.Name); failedMu.Unlock() },
	}
	n.SetRoutes([]Route{
		{Destination: hook("1"), Events: map[string]bool{audit.ActionLogin: true}},
		{Destination: hook("2"), Events: map[string]bool{audit.ActionDomainAdd: true, EventProtectedGroupAdd: true}},
		{Destination: hook("3"), Events: map[string]bool{EventProtectedGroupAdd: true}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()

	paths := func() map[string]int {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := map[string]int{}
		for _, r := range f.got {
			out[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/webhooks/"), "/tok")]++
		}
		return out
	}
	waitFor := func(cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out; requests %v, failed %v", paths(), failed)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// A login goes to hook 1 only; a client update with protected groups goes to hooks 2 and 3 as alerts.
	n.Notify(audit.Entry{Username: "alice", Action: audit.ActionLogin})
	n.Notify(audit.Entry{Username: "alice", Action: audit.ActionClientUpdate,
		Detail: map[string]any{"client": "10.0.0.9", "protected_added": []string{"Kids"}}})
	n.Notify(audit.Entry{Username: "alice", Action: audit.ActionLogout}) // nobody wants it
	waitFor(func() bool { p := paths(); return p["1"] == 1 && p["2"] == 1 && p["3"] == 1 })
	f.mu.Lock()
	alerts := strings.Count(strings.Join(f.bodies, ""), "protected group")
	f.mu.Unlock()
	if alerts != 2 {
		t.Errorf("%d protected-group alerts, want 2", alerts)
	}

	// Two failures, then success: three requests, no Failed.
	mu.Lock()
	fails["/api/webhooks/2/tok"] = 2
	mu.Unlock()
	n.Notify(audit.Entry{Username: "alice", Action: audit.ActionDomainAdd})
	waitFor(func() bool { return paths()["2"] == 4 })

	// A guard that keeps failing: an attempt and three retries, then Failed once.
	mu.Lock()
	fails["/api/webhooks/5/tok"] = 100
	mu.Unlock()
	n.Enqueue(Job{Destination: hook("5"), Message: &Message{}, Event: "guard", Guard: true})
	// A guard the destination refuses: no retries, Failed at once. An ordinary message that's refused isn't reported.
	n.Enqueue(Job{Destination: hook("404"), Message: &Message{}, Event: "guard", Guard: true})
	n.Enqueue(Job{Destination: hook("404"), Message: &Message{}, Event: audit.ActionLogin})
	waitFor(func() bool {
		failedMu.Lock()
		defer failedMu.Unlock()
		return len(failed) == 2
	})
	time.Sleep(50 * time.Millisecond)
	if p := paths(); p["5"] != 4 || p["404"] != 2 {
		t.Errorf("requests %v: want 4 to hook 5 and 2 to hook 404", p)
	}
	failedMu.Lock()
	if len(failed) != 2 {
		t.Errorf("Failed called for %v", failed)
	}
	failedMu.Unlock()

	cancel()
	<-done
	// After stopping, nothing is queued.
	if n.Enqueue(Job{Destination: hook("1"), Message: &Message{}}) {
		t.Error("queued after stopping")
	}
}

func TestQueueFull(t *testing.T) {
	var failed []string
	n := &Notifier{QueueSize: 2, Failed: func(j Job, r Result) { failed = append(failed, j.Event) }}
	d := discordDest()
	for i := range 3 {
		n.Enqueue(Job{Destination: d, Message: &Message{}, Event: "e" + string(rune('0'+i))})
	}
	if n.Enqueue(Job{Destination: d, Message: &Message{}, Event: "guard", Guard: true}) {
		t.Fatal("a full queue took a job")
	}
	if n.dropped.Load() != 2 || len(failed) != 1 || failed[0] != "guard" {
		t.Errorf("dropped %d, failed %v", n.dropped.Load(), failed)
	}
}

// The audit logger hands every logged entry to its sink, after the line is written.
func TestAuditSink(t *testing.T) {
	l := audit.NewLogger(io.Discard)
	var got []string
	l.SetSink(func(e audit.Entry) { got = append(got, e.Action) })
	l.Log(audit.Entry{Username: "a", Action: audit.ActionLogin})
	l.Log(audit.Entry{Username: "a", Action: audit.ActionLogout, Err: errors.New("x")})
	l.SetSink(nil)
	l.Log(audit.Entry{Username: "a", Action: audit.ActionSetup})
	if strings.Join(got, ",") != "login,logout" {
		t.Errorf("sink got %v", got)
	}
}
