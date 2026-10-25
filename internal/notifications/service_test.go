// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// fakeSecrets is the secrets manager: a cipher (or none) and the channel variables that are set.
type fakeSecrets struct {
	cipher *secrets.Cipher
	env    map[string]string
}

func (f *fakeSecrets) Cipher() *secrets.Cipher { return f.cipher }
func (f *fakeSecrets) ChannelSecret(name string) (secrets.Value, bool) {
	v, ok := f.env[name]
	return secrets.NewValue([]byte(v)), ok && v != ""
}

func newCipher(t *testing.T, b byte) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher(bytes.Repeat([]byte{b}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sink is an HTTPS server standing in for every destination. A webhook whose ID is in refuse gets a 404.
type sink struct {
	srv    *httptest.Server
	mu     sync.Mutex
	posts  []post
	refuse map[string]bool
}

type post struct {
	path string // without the /api/webhooks/ prefix, e.g. "11/tok"
	text string // Discord content, or Matrix body
	auth string
}

func newSink(t *testing.T) *sink {
	k := &sink{refuse: map[string]bool{}}
	k.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		text, _ := body["content"].(string)
		if text == "" {
			text, _ = body["body"].(string)
		}
		p := post{path: strings.TrimPrefix(r.URL.Path, "/api/webhooks/"), text: text, auth: r.Header.Get("Authorization")}
		k.mu.Lock()
		k.posts = append(k.posts, p)
		refused := k.refuse[strings.SplitN(p.path, "/", 2)[0]]
		k.mu.Unlock()
		if refused {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *sink) client() *http.Client {
	addr := k.srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // the fake's certificate; only in tests
	}}
}

// to returns what was sent to a webhook ID (or, for Matrix, to any path holding it), in order.
func (k *sink) to(id string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for _, p := range k.posts {
		if strings.HasPrefix(p.path, id+"/") || strings.Contains(p.path, id) {
			out = append(out, p.text)
		}
	}
	return out
}

func (k *sink) waitFor(t *testing.T, id string, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := k.to(id)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d messages to %s, got %v", n, id, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type env struct {
	t      *testing.T
	st     *store.Store
	svc    *Service
	sec    *fakeSecrets
	sink   *sink
	audit  *bytes.Buffer
	admin  rbac.Actor
	nobody rbac.Actor
}

func newEnv(t *testing.T) *env {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var buf bytes.Buffer
	al := audit.NewLogger(&buf)
	k := newSink(t)
	n := &notify.Notifier{Sender: &notify.Sender{Client: k.client()}, Delays: []time.Duration{time.Millisecond}}
	sec := &fakeSecrets{cipher: newCipher(t, 1), env: map[string]string{}}
	svc := &Service{Store: st, Audit: al, Secrets: sec, Notifier: n, Logger: quiet}
	n.Failed = svc.GuardFailed
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go n.Run(ctx)

	var noneRole int64
	if err := st.WithTx(context.Background(), func(q *db.Queries) error {
		var err error
		noneRole, err = q.CreateRole(context.Background(), db.CreateRoleParams{Name: "none", CreatedAt: 1})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return &env{
		t: t, st: st, svc: svc, sec: sec, sink: k, audit: &buf,
		admin:  rbac.Actor{Username: "admin", RoleIDs: []int64{1}, IP: "10.0.0.1"},
		nobody: rbac.Actor{Username: "nobody", RoleIDs: []int64{noneRole}, IP: "10.0.0.2"},
	}
}

func (e *env) rows() []db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(context.Background(), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return rows // newest first
}

func val(s string) *secrets.Value { v := secrets.NewValue([]byte(s)); return &v }

func hook(id string) string { return "https://discord.com/api/webhooks/" + id + "/tok" + id }

func code(err error) string {
	if e, ok := rbac.AsError(err); ok {
		return string(e.Code)
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

func field(err error) string {
	if e, ok := rbac.AsError(err); ok {
		f, _ := e.Details["field"].(string)
		return f
	}
	return ""
}

func TestCreateDiscord(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch, err := e.svc.Create(ctx, e.admin, Input{
		Kind: notify.Discord, Name: " Ops ", Enabled: true, Secret: val("https://DISCORD.com/api/webhooks/11/tok11"),
		Events: []string{audit.ActionLogout, audit.ActionLogin, audit.ActionLogin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Name != "Ops" || ch.WebhookID != "11" || ch.SecretSource != SourceStored || ch.SecretUpdatedBy != "admin" ||
		ch.SecretProblem != "" || strings.Join(ch.Events, ",") != "login,logout" {
		t.Errorf("channel: %+v", ch)
	}
	row := e.rows()[0]
	if row.Action != audit.ActionChannelCreate || row.Target != "channel:Ops" || !strings.Contains(row.Detail, `"secret":"stored"`) ||
		!strings.Contains(row.Detail, `"webhook_id":"11"`) || strings.Contains(row.Detail, "tok11") {
		t.Errorf("audit row: %+v", row)
	}
	// The stored secret is sealed to its row.
	raw, _ := e.st.Read().GetChannel(ctx, ch.ID)
	if bytes.Contains(raw.SecretCiphertext, []byte("tok11")) || raw.Config != `{"webhook_id":"11"}` {
		t.Errorf("stored row: %s %q", raw.Config, raw.SecretCiphertext)
	}

	// The routes follow: a login is sent, a domain_add isn't.
	e.svc.Notifier.Notify(audit.Entry{Username: "alice", Action: audit.ActionDomainAdd})
	e.svc.Notifier.Notify(audit.Entry{Username: "alice", Action: audit.ActionLogin})
	if got := e.sink.waitFor(t, "11", 1); len(got) != 1 || !strings.Contains(got[0], "alice") || !strings.Contains(got[0], "login") {
		t.Errorf("sent %v", got)
	}

	// No secret: allowed, but it can't send.
	none, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "later", Enabled: true, Events: []string{audit.ActionLogin}})
	if err != nil || none.SecretSource != SourceNone || none.SecretProblem == "" {
		t.Errorf("without a secret: %+v, %v", none, err)
	}
}

func TestInputRules(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Ops", EnvName: "OPS", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	m := notify.MatrixConfig{Homeserver: "https://matrix.example.org", RoomID: "!r:example.org"}
	for _, tt := range []struct {
		name  string
		in    Input
		code  string
		field string
	}{
		{"kind", Input{Kind: "slack", Name: "x"}, "validation_failed", "kind"},
		{"empty name", Input{Kind: notify.Discord, Name: "  "}, "validation_failed", "name"},
		{"long name", Input{Kind: notify.Discord, Name: strings.Repeat("n", 65)}, "validation_failed", "name"},
		{"control in name", Input{Kind: notify.Discord, Name: "a\nb"}, "validation_failed", "name"},
		{"env name", Input{Kind: notify.Discord, Name: "x", EnvName: "lower"}, "validation_failed", "env_name"},
		{"unknown event", Input{Kind: notify.Discord, Name: "x", Events: []string{"no_such"}}, "validation_failed", "events"},
		{"bad webhook", Input{Kind: notify.Discord, Name: "x", Secret: val("https://evil.example/api/webhooks/1/x")}, "validation_failed", "secret"},
		{"no homeserver", Input{Kind: notify.Matrix, Name: "x"}, "validation_failed", "homeserver"},
		{"plain http", Input{Kind: notify.Matrix, Name: "x", Matrix: notify.MatrixConfig{Homeserver: "http://m.lan", RoomID: "!r:lan"}}, "validation_failed", "homeserver"},
		{"room alias", Input{Kind: notify.Matrix, Name: "x", Matrix: notify.MatrixConfig{Homeserver: "https://m.lan", RoomID: "#r:lan"}}, "validation_failed", "room_id"},
		{"bad token", Input{Kind: notify.Matrix, Name: "x", Matrix: m, Secret: val("has space")}, "validation_failed", "secret"},
		{"name taken, any case", Input{Kind: notify.Discord, Name: "OPS"}, "conflict", "name"},
		{"env name taken", Input{Kind: notify.Discord, Name: "y", EnvName: "OPS"}, "conflict", "env_name"},
	} {
		_, err := e.svc.Create(ctx, e.admin, tt.in)
		if code(err) != tt.code || field(err) != tt.field {
			t.Errorf("%s: %v (%s, %s)", tt.name, err, code(err), field(err))
		}
	}
	// Without a master key, a secret can't be stored.
	e.sec.cipher = nil
	_, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "z", Secret: val(hook("5"))})
	if code(err) != "validation_failed" || field(err) != "secret" || !strings.Contains(err.Error(), "master key") {
		t.Errorf("no master key: %v", err)
	}
	if n := len(e.rows()); n != 1 {
		t.Errorf("%d audit rows: refused input was audited", n)
	}
}

// A Matrix token is only sent to the homeserver it was entered for, and a variable only used once confirmed.
func TestConfirmationRule(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	m := notify.MatrixConfig{Homeserver: "https://matrix.example.org", RoomID: "!r:example.org"}
	ch, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Matrix, Name: "room", Enabled: true, Matrix: m, Secret: val("syt_one")})
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Kind: notify.Matrix, Name: "room", Enabled: true, Matrix: m}

	moved := in
	moved.Matrix.Homeserver = "https://attacker.example"
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, moved); field(err) != "secret" {
		t.Errorf("a new homeserver without the token: %v", err)
	}
	insecure := in
	insecure.Matrix.Homeserver, insecure.Matrix.AllowHTTP = "http://matrix.example.org", true
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, insecure); field(err) != "secret" {
		t.Errorf("allowing plain HTTP without the token: %v", err)
	}
	// Another room on the same homeserver needs no token: it goes to the same server.
	room := in
	room.Matrix.RoomID = "!other:example.org"
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, room); err != nil {
		t.Errorf("a new room: %v", err)
	}
	moved.Matrix.RoomID = room.Matrix.RoomID
	moved.Secret = val("syt_two")
	if got, err := e.svc.Update(ctx, e.admin, ch.ID, moved); err != nil || got.Matrix.Homeserver != "https://attacker.example" {
		t.Errorf("a new homeserver with the token: %+v, %v", got, err)
	}

	// A channel that starts using a variable that is set must give its value.
	e.sec.env["ROOM"] = "syt_env"
	withVar := moved
	withVar.Secret, withVar.EnvName = nil, "ROOM"
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, withVar); field(err) != "secret" {
		t.Errorf("a set variable without its value: %v", err)
	}
	withVar.Secret = val("syt_wrong")
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, withVar); field(err) != "secret" || !strings.Contains(err.Error(), "isn't the access token in") {
		t.Errorf("the wrong value: %v", err)
	}
	withVar.Secret = val("syt_env")
	got, err := e.svc.Update(ctx, e.admin, ch.ID, withVar)
	if err != nil || got.SecretSource != SourceEnvironment || got.SecretVariable != "PIHOLE_RBAC_NOTIFY_ROOM_SECRET" {
		t.Fatalf("confirmed: %+v, %v", got, err)
	}
	if row := e.rows()[0]; !strings.Contains(row.Detail, `"secret":"confirmed"`) {
		t.Errorf("audit row: %s", row.Detail)
	}
	// Created with a set variable: the same.
	if _, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Matrix, Name: "two", EnvName: "ROOM", Matrix: m}); field(err) != "secret" {
		t.Errorf("created with a set variable: %v", err)
	}
	// A secret set from the environment can't be replaced here.
	if _, err := e.svc.SetSecret(ctx, e.admin, ch.ID, secrets.NewValue([]byte("syt_x"))); code(err) != "conflict" {
		t.Errorf("replacing an environment secret: %v", err)
	}
}

// Changing where a channel sends, disabling it, taking events away or deleting it warns the old destination.
func TestGuards(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	in := Input{Kind: notify.Discord, Name: "Ops", Enabled: true, Secret: val(hook("21")),
		Events: []string{audit.ActionLogin, audit.ActionLogout}}
	ch, err := e.svc.Create(ctx, e.admin, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Secret = nil

	// Events taken away from an enabled channel.
	in.Events = []string{audit.ActionLogin}
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, in); err != nil {
		t.Fatal(err)
	}
	got := e.sink.waitFor(t, "21", 1)
	if !strings.Contains(got[0], "admin") || !strings.Contains(got[0], "no longer receives logout") {
		t.Errorf("events guard: %q", got[0])
	}

	// A new webhook: the old one hears about it; messages then go to the new one.
	in.Secret = val(hook("22"))
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, in); err != nil {
		t.Fatal(err)
	}
	in.Secret = nil
	got = e.sink.waitFor(t, "21", 2)
	if !strings.Contains(got[1], "messages now go elsewhere") {
		t.Errorf("destination guard: %q", got[1])
	}
	e.svc.Notifier.Notify(audit.Entry{Username: "alice", Action: audit.ActionLogin})
	e.sink.waitFor(t, "22", 1)

	// The secret replaced on its own.
	if _, err := e.svc.SetSecret(ctx, e.admin, ch.ID, secrets.NewValue([]byte(hook("23")))); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.waitFor(t, "22", 2); !strings.Contains(got[1], "replaced") {
		t.Errorf("secret guard: %q", got[1])
	}

	// Disabled: told once. Changes while disabled warn only about the destination.
	in.Enabled = false
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, in); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.waitFor(t, "23", 1); !strings.Contains(got[0], "disabled") {
		t.Errorf("disable guard: %q", got[0])
	}
	in.Events = nil
	if _, err := e.svc.Update(ctx, e.admin, ch.ID, in); err != nil {
		t.Fatal(err)
	}

	// Deleting a disabled channel says nothing; an enabled one is told.
	if err := e.svc.Delete(ctx, e.admin, ch.ID); err != nil {
		t.Fatal(err)
	}
	other, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Other", Enabled: true, Secret: val(hook("24"))})
	if err := e.svc.Delete(ctx, e.admin, other.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.waitFor(t, "24", 1); !strings.Contains(got[0], "deleted") {
		t.Errorf("delete guard: %q", got[0])
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(e.sink.to("23")); n != 1 {
		t.Errorf("%d messages to the disabled channel, want only the disable warning", n)
	}
	for _, r := range e.rows() {
		if strings.Contains(r.Detail, "tok2") {
			t.Errorf("a webhook token reached the audit log: %s %s", r.Action, r.Detail)
		}
	}

	// A renamed channel without a secret change, or a new event, warns nobody.
	third, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Third", Enabled: true, Secret: val(hook("25"))})
	if _, err := e.svc.Update(ctx, e.admin, third.ID, Input{Kind: notify.Discord, Name: "Third renamed", Enabled: true,
		Events: []string{audit.ActionLogin}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := e.sink.to("25"); len(got) != 0 {
		t.Errorf("a harmless change warned: %v", got)
	}
}

// A warning the old destination refuses is audited as notification_failed, with who made the change.
func TestGuardFailedAudited(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.sink.refuse["31"] = true
	ch, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Gone", Enabled: true, Secret: val(hook("31"))})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(ctx, e.admin, ch.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.rows()[0].Action != audit.ActionNotificationFailed {
		if time.Now().After(deadline) {
			t.Fatalf("no notification_failed row: %v", e.rows()[0].Action)
		}
		time.Sleep(5 * time.Millisecond)
	}
	r := e.rows()[0]
	if r.Username != audit.SystemUser || r.Result != audit.ResultFailure || r.Target != "channel:Gone" ||
		!strings.Contains(r.Detail, `"changed_by":"admin"`) || !strings.Contains(r.Detail, `"status":404`) || strings.Contains(r.Detail, "tok31") {
		t.Errorf("row: %+v", r)
	}
}

func TestPermission(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Ops", Enabled: true, Secret: val(hook("41"))})
	before := len(e.rows())
	in := Input{Kind: notify.Discord, Name: "Ops", Enabled: false}
	errs := map[string]error{}
	_, errs["create"] = e.svc.Create(ctx, e.nobody, in)
	_, errs["update"] = e.svc.Update(ctx, e.nobody, ch.ID, in)
	_, errs["secret"] = e.svc.SetSecret(ctx, e.nobody, ch.ID, secrets.NewValue([]byte(hook("42"))))
	errs["delete"] = e.svc.Delete(ctx, e.nobody, ch.ID)
	_, errs["test"] = e.svc.Test(ctx, e.nobody, ch.ID)
	for name, err := range errs {
		if code(err) != "forbidden" {
			t.Errorf("%s: %v", name, err)
		}
	}
	rows := e.rows()
	if len(rows) != before+5 {
		t.Fatalf("%d new rows, want 5 refusals", len(rows)-before)
	}
	for _, r := range rows[:5] {
		if r.Action != audit.ActionPermissionDenied || r.Username != "nobody" || !strings.Contains(r.Detail, "notifications.manage") {
			t.Errorf("refusal row: %+v", r)
		}
	}
	if got, _ := e.svc.Get(ctx, ch.ID); !got.Enabled {
		t.Error("the channel changed")
	}
	time.Sleep(30 * time.Millisecond)
	if got := e.sink.to("41"); len(got) != 0 {
		t.Errorf("a refused change sent %v", got)
	}
}

func TestSendTest(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Ops", Enabled: false, Secret: val(hook("51"))})
	r, err := e.svc.Test(ctx, e.admin, ch.ID)
	if err != nil || !r.OK || r.Status != http.StatusNoContent {
		t.Fatalf("test: %+v, %v", r, err)
	}
	if got := e.sink.to("51"); len(got) != 1 || !strings.Contains(got[0], "Test message") {
		t.Errorf("sent %v", got)
	}
	e.sink.refuse["51"] = true
	if r, _ := e.svc.Test(ctx, e.admin, ch.ID); r.OK || r.Status != http.StatusNotFound || r.Message == "" {
		t.Errorf("refused: %+v", r)
	}
	none, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Empty"})
	if _, err := e.svc.Test(ctx, e.admin, none.ID); code(err) != "conflict" {
		t.Errorf("no secret: %v", err)
	}
	if _, err := e.svc.Test(ctx, e.admin, 999); code(err) != "not_found" {
		t.Errorf("missing: %v", err)
	}
	for _, r := range e.rows() {
		if r.Action == actionChannelTest {
			t.Error("a test was audited")
		}
	}

	// Matrix sends the token as a Bearer header to the homeserver.
	mx, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Matrix, Name: "Room", Secret: val("syt_tok"),
		Matrix: notify.MatrixConfig{Homeserver: "https://matrix.example.org", RoomID: "!room61:example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := e.svc.Test(ctx, e.admin, mx.ID); err != nil || !r.OK {
		t.Fatalf("matrix test: %+v, %v", r, err)
	}
	e.sink.mu.Lock()
	last := e.sink.posts[len(e.sink.posts)-1]
	e.sink.mu.Unlock()
	if last.auth != "Bearer syt_tok" || !strings.Contains(last.path, "room61") {
		t.Errorf("matrix request: %+v", last)
	}
}

// A secret stored under another master key can't be read: the channel says why and isn't routed.
func TestUnreadableSecret(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ch, _ := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Ops", Enabled: true, Secret: val(hook("71")),
		Events: []string{audit.ActionLogin}})
	e.sec.cipher = newCipher(t, 2)
	got, _ := e.svc.Get(ctx, ch.ID)
	if got.SecretSource != SourceStored || !strings.Contains(got.SecretProblem, "current master key") {
		t.Errorf("channel: %+v", got)
	}
	if err := e.svc.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	e.svc.Notifier.Notify(audit.Entry{Username: "alice", Action: audit.ActionLogin})
	time.Sleep(50 * time.Millisecond)
	if n := len(e.sink.to("71")); n != 0 {
		t.Errorf("an unreadable channel sent %d messages", n)
	}
	// A variable that holds something that isn't a webhook URL is a problem too.
	e.sec.env["OPS"] = "not a url"
	ch2, err := e.svc.Create(ctx, e.admin, Input{Kind: notify.Discord, Name: "Env", EnvName: "OPS2"})
	if err != nil {
		t.Fatal(err)
	}
	e.sec.env["OPS2"] = "https://evil.example/x"
	if got, _ := e.svc.Get(ctx, ch2.ID); got.SecretSource != SourceEnvironment || !strings.Contains(got.SecretProblem, "valid webhook URL") {
		t.Errorf("bad variable: %+v", got)
	}
}

func TestEvents(t *testing.T) {
	ev := Events()
	for i, e := range ev {
		if e.Name == audit.ActionClientUpdate {
			if ev[i+1].Name != notify.EventProtectedGroupAdd {
				t.Errorf("protected_group_add doesn't follow client_update: %s", ev[i+1].Name)
			}
			return
		}
	}
	t.Error("client_update isn't listed")
}
