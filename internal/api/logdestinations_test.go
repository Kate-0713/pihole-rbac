// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/logdestinations"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

func withLogDestinations(t *testing.T) func(*Options) {
	return func(o *Options) {
		svc := &logdestinations.Service{
			Store: o.Store, Audit: o.Audit, Hostname: "test", Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(func() { cancel(); svc.Wait() })
		if err := svc.Start(ctx); err != nil {
			t.Fatal(err)
		}
		o.LogDestinations = svc
	}
}

func TestLogDestinationLifecycle(t *testing.T) {
	e := newTestEnv(t, withLogDestinations(t))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	col := syslogtest.NewTCP(t)
	const path = "/api/v1/settings/log-destinations"
	in := gen.LogDestinationInput{Name: "Main", Host: col.Host, Port: col.Port, Transport: ptr(gen.LogTransport("tcp")), Enabled: true}

	// Plain tcp asks first.
	res := c.do(http.MethodPost, path, in)
	var errBody gen.Error
	_ = decodeInto(res, &errBody)
	if res.Code != http.StatusConflict || errBody.Error.Code != "confirmation_required" {
		t.Fatalf("unconfirmed create: %d %s", res.Code, res.Body)
	}
	mustStatus(t, c.do(http.MethodPost, path+"?confirm=true", in), http.StatusCreated)

	var list gen.LogDestinationList
	res = c.do(http.MethodGet, path, nil)
	mustStatus(t, res, http.StatusOK)
	if err := decodeInto(res, &list); err != nil || len(list.Destinations) != 1 {
		t.Fatalf("list: %v %s", err, res.Body)
	}
	d := list.Destinations[0]
	if d.Name != "Main" || d.Transport != "tcp" || d.TlsMode != "verify" || d.CreatedBy != "admin" ||
		d.Status.Delivery != gen.AtLeastOnce {
		t.Fatalf("destination %+v", d)
	}

	one := fmt.Sprintf("%s/%d", path, d.Id)
	mustStatus(t, c.do(http.MethodGet, one, nil), http.StatusOK)
	in.Name = "Renamed"
	mustStatus(t, c.do(http.MethodPut, one, in), http.StatusOK)

	res = c.do(http.MethodPost, one+"/test", nil)
	mustStatus(t, res, http.StatusOK)
	var tr gen.LogDestinationTestResult
	if err := decodeInto(res, &tr); err != nil || !tr.Ok {
		t.Fatalf("test: %v %s", err, res.Body)
	}

	mustStatus(t, c.do(http.MethodDelete, one, nil), http.StatusNoContent)
	mustStatus(t, c.do(http.MethodGet, one, nil), http.StatusNotFound)
	mustStatus(t, c.do(http.MethodPost, one+"/test", nil), http.StatusNotFound)
}

func TestLogDestinationRefusals(t *testing.T) {
	e := newTestEnv(t, withLogDestinations(t))
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("viewer", "viewer-password", rbac.DomainsView, rbac.SettingsManage, rbac.NotifyManage)
	c := e.loggedIn("admin", "admin-password-1")
	const path = "/api/v1/settings/log-destinations"

	for _, tt := range []struct {
		body  gen.LogDestinationInput
		field string
	}{
		{gen.LogDestinationInput{Name: "", Host: "logs.lan", Port: 6514}, "name"},
		{gen.LogDestinationInput{Name: "x", Host: "https://logs.lan", Port: 6514}, "host"},
		{gen.LogDestinationInput{Name: "x", Host: "logs.lan", Port: 0}, "port"},
		{gen.LogDestinationInput{Name: "x", Host: "logs.lan", Port: 6514, CaFile: ptr("ca.pem")}, "ca_file"},
	} {
		res := c.do(http.MethodPost, path, tt.body)
		var body gen.Error
		_ = decodeInto(res, &body)
		if res.Code != 400 || body.Error.Details == nil || (*body.Error.Details)["field"] != tt.field {
			t.Errorf("%+v: %d %s", tt.body, res.Code, res.Body)
		}
	}

	// Without logging.manage, every route is refused, whatever else the role holds.
	v := e.loggedIn("viewer", "viewer-password")
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, path},
		{http.MethodPost, path},
		{http.MethodGet, path + "/1"},
		{http.MethodPut, path + "/1"},
		{http.MethodDelete, path + "/1"},
		{http.MethodPost, path + "/1/test"},
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
