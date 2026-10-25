// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// channelSecrets is a master key and no channel variables.
type channelSecrets struct{ cipher *secrets.Cipher }

func (c channelSecrets) Cipher() *secrets.Cipher                  { return c.cipher }
func (channelSecrets) ChannelSecret(string) (secrets.Value, bool) { return secrets.Value{}, false }

// withNotifications gives the server a notifications service whose destinations are all one fake HTTPS server, which
// counts what it receives.
func withNotifications(t *testing.T, received *[]string, mu *sync.Mutex) func(*Options) {
	return func(o *Options) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			*received = append(*received, r.URL.Path+" "+string(b))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(srv.Close)
		addr := srv.Listener.Addr().String()
		client := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // the fake's certificate; only in tests
		}}
		c, err := secrets.NewCipher(bytes.Repeat([]byte{3}, secrets.KeySize))
		if err != nil {
			t.Fatal(err)
		}
		n := &notify.Notifier{Sender: &notify.Sender{Client: client}}
		o.Notifications = &notifications.Service{
			Store: o.Store, Audit: o.Audit, Secrets: channelSecrets{cipher: c}, Notifier: n,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
	}
}

const testHook = "https://discord.com/api/webhooks/81/secret-token-81"

func TestChannelLifecycle(t *testing.T) {
	var mu sync.Mutex
	var received []string
	e := newTestEnv(t, withNotifications(t, &received, &mu))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	noSecret := func(res response) {
		t.Helper()
		if strings.Contains(res.Body.String(), "secret-token") {
			t.Errorf("a response holds the webhook token: %s", res.Body)
		}
	}

	res := c.do(http.MethodPost, "/api/v1/notifications/channels", gen.ChannelInput{
		Kind: "discord", Name: "Ops", Enabled: true, Events: []string{"login", "domain_add"}, Secret: ptr(testHook),
	})
	mustStatus(t, res, http.StatusCreated)
	noSecret(res)
	ch := decode[gen.Channel](t, res)
	if ch.SecretSource != "stored" || ch.WebhookId == nil || *ch.WebhookId != "81" || strings.Join(ch.Events, ",") != "domain_add,login" ||
		ch.SecretUpdatedBy == nil || *ch.SecretUpdatedBy != "admin" || ch.Matrix != nil {
		t.Errorf("created: %+v", ch)
	}
	path := fmt.Sprintf("/api/v1/notifications/channels/%d", ch.Id)

	res = c.do(http.MethodGet, "/api/v1/notifications/channels", nil)
	mustStatus(t, res, http.StatusOK)
	noSecret(res)
	if l := decode[gen.ChannelList](t, res); len(l.Channels) != 1 || !l.CanStoreSecrets {
		t.Errorf("list: %+v", l)
	}
	mustStatus(t, c.do(http.MethodGet, path, nil), http.StatusOK)

	// A change, and its audit row.
	res = c.do(http.MethodPut, path, gen.ChannelInput{Kind: "discord", Name: "Ops", Enabled: true, Events: []string{"login"}})
	mustStatus(t, res, http.StatusOK)
	if got := decode[gen.Channel](t, res); strings.Join(got.Events, ",") != "login" {
		t.Errorf("updated: %+v", got)
	}
	rows := e.auditRows()
	if last := rows[len(rows)-1]; last.Action != "channel_update" || !strings.Contains(last.Detail, `"events_removed":["domain_add"]`) {
		t.Errorf("audit row: %+v", last)
	}

	// Send test; a new secret; delete.
	res = c.do(http.MethodPost, path+"/test", nil)
	mustStatus(t, res, http.StatusOK)
	if r := decode[gen.ChannelTestResult](t, res); !r.Ok || r.Status == nil || *r.Status != http.StatusNoContent {
		t.Errorf("test: %+v", r)
	}
	res = c.do(http.MethodPut, path+"/secret", gen.ChannelSecret{Secret: ptr("https://discord.com/api/webhooks/82/secret-token-82")})
	mustStatus(t, res, http.StatusOK)
	noSecret(res)
	if got := decode[gen.Channel](t, res); *got.WebhookId != "82" {
		t.Errorf("after a new secret: %+v", got)
	}
	mustStatus(t, c.do(http.MethodDelete, path, nil), http.StatusNoContent)
	if res := c.do(http.MethodGet, path, nil); res.Code != http.StatusNotFound {
		t.Errorf("after delete: %d", res.Code)
	}
	for _, r := range e.auditRows() {
		if strings.Contains(r.Detail, "secret-token") {
			t.Errorf("the token reached the audit log: %s", r.Detail)
		}
	}
	for _, l := range e.auditLines() {
		if strings.Contains(l, "secret-token") {
			t.Errorf("the token reached an AUDIT line: %s", l)
		}
	}

	// The events a channel can receive.
	ev := decode[gen.NotificationEventList](t, c.do(http.MethodGet, "/api/v1/notifications/events", nil))
	found := false
	for _, x := range ev.Events {
		if x.Name == notify.EventProtectedGroupAdd && x.Group != "" && x.Description != "" {
			found = true
		}
	}
	if !found || len(ev.Events) < 40 {
		t.Errorf("%d events, protected_group_add listed: %v", len(ev.Events), found)
	}
}

func TestChannelRefusals(t *testing.T) {
	var mu sync.Mutex
	var received []string
	e := newTestEnv(t, withNotifications(t, &received, &mu))
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("viewer", "viewer-password", rbac.DomainsView, rbac.SettingsManage)
	c := e.loggedIn("admin", "admin-password-1")
	mustStatus(t, c.do(http.MethodPost, "/api/v1/notifications/channels",
		gen.ChannelInput{Kind: "discord", Name: "Ops", Enabled: true, Events: []string{}}), http.StatusCreated)

	for _, tt := range []struct {
		body   gen.ChannelInput
		status int
		field  string
	}{
		{gen.ChannelInput{Kind: "discord", Name: "x", Events: []string{}, Secret: ptr("https://example.com/hook")}, 400, "secret"},
		{gen.ChannelInput{Kind: "matrix", Name: "x", Events: []string{}}, 400, "homeserver"},
		{gen.ChannelInput{Kind: "matrix", Name: "x", Events: []string{},
			Matrix: &gen.ChannelMatrix{Homeserver: "http://m.lan", RoomId: "!r:lan"}}, 400, "homeserver"},
		{gen.ChannelInput{Kind: "discord", Name: "x", Events: []string{"nope"}}, 400, "events"},
		{gen.ChannelInput{Kind: "slack", Name: "x", Events: []string{}}, 400, "kind"},
		{gen.ChannelInput{Kind: "discord", Name: "ops", Events: []string{}}, 409, "name"},
	} {
		res := c.do(http.MethodPost, "/api/v1/notifications/channels", tt.body)
		var body gen.Error
		_ = decodeInto(res, &body)
		if res.Code != tt.status || body.Error.Details == nil || (*body.Error.Details)["field"] != tt.field {
			t.Errorf("%+v: %d %s", tt.body, res.Code, res.Body)
		}
	}
	// A kind can't change.
	if res := c.do(http.MethodPut, "/api/v1/notifications/channels/1", gen.ChannelInput{Kind: "matrix", Name: "Ops", Events: []string{},
		Matrix: &gen.ChannelMatrix{Homeserver: "https://m.lan", RoomId: "!r:lan"}}); res.Code != 400 {
		t.Errorf("kind change: %d %s", res.Code, res.Body)
	}
	if res := c.do(http.MethodPut, "/api/v1/notifications/channels/1/secret", map[string]any{}); res.Code != 400 {
		t.Errorf("no secret: %d", res.Code)
	}
	if res := c.do(http.MethodPost, "/api/v1/notifications/channels/1/test", nil); res.Code != 409 {
		t.Errorf("test without a secret: %d %s", res.Code, res.Body)
	}
	if res := c.do(http.MethodGet, "/api/v1/notifications/channels/99", nil); res.Code != 404 {
		t.Errorf("missing: %d", res.Code)
	}

	// Without notifications.manage, every route is refused, settings.manage or not.
	v := e.loggedIn("viewer", "viewer-password")
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/notifications/channels"},
		{http.MethodPost, "/api/v1/notifications/channels"},
		{http.MethodGet, "/api/v1/notifications/channels/1"},
		{http.MethodPut, "/api/v1/notifications/channels/1"},
		{http.MethodDelete, "/api/v1/notifications/channels/1"},
		{http.MethodPut, "/api/v1/notifications/channels/1/secret"},
		{http.MethodPost, "/api/v1/notifications/channels/1/test"},
		{http.MethodGet, "/api/v1/notifications/events"},
	} {
		var body any
		if r.method == http.MethodPost || r.method == http.MethodPut {
			body = map[string]any{}
		}
		if res := v.do(r.method, r.path, body); res.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d", r.method, r.path, res.Code)
		}
	}
}

func decodeInto(res response, v any) error {
	return json.Unmarshal(res.Body.Bytes(), v)
}
