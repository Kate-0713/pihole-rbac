// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

type protectedEntry = struct {
	Id           int64                   `json:"id"`
	PiholeGroups []string                `json:"pihole_groups"`
	Scope        gen.ProtectedGroupScope `json:"scope"`
}

// A client update records the protected groups the client was added to, by the rules for each member: its own
// protected groups and its mirrored group's, however it was reached. A channel that wants protected_group_add gets an
// alert, and taking a protected group away tells it.
func TestProtectedGroupAlerts(t *testing.T) {
	var mu sync.Mutex
	var received []string
	ge := newGroupEnv(t, withNotifications(t, &received, &mu))
	// The notifier as serve runs it: every audit entry goes to it.
	n := ge.srv.Notifications.Notifier
	ge.srv.Audit.SetSink(n.Notify)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	// The same Pi-hole groups, in the same order, on every member, and one client.
	var kids, guests int
	for _, name := range []string{"alpha", "beta", "gamma"} {
		kids, guests = ge.ph[name].AddGroup("Kids"), ge.ph[name].AddGroup("Guests")
		ge.ph[name].AddClient(piholetest.Client{Client: "10.0.0.9", Groups: []int{0}})
	}

	// Kids is protected on alpha alone; guests (any case) on the mirrored group.
	res := ge.admin.do(http.MethodPut, "/api/v1/notifications/protected-groups", gen.ProtectedGroupsInput{Entries: []protectedEntry{
		{Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{" kids ", "KIDS"}},
		{Scope: "group", Id: ge.groupID, PiholeGroups: []string{"guests"}},
		{Scope: "instance", Id: ge.ids["beta"], PiholeGroups: []string{}},
	}})
	mustStatus(t, res, http.StatusOK)
	got := decode[gen.ProtectedGroupSettings](t, res)
	if len(got.Entries) != 2 || got.Entries[0].Name != "alpha" || strings.Join(got.Entries[0].PiholeGroups, ",") != "kids" ||
		got.Entries[1].Scope != "group" || got.Entries[1].Name != "site" || len(got.Instances) != 3 || len(got.Groups) != 1 {
		t.Fatalf("saved: %+v", got)
	}
	rows := ge.auditRows()
	if last := rows[len(rows)-1]; last.Action != "protected_groups_update" ||
		!strings.Contains(last.Detail, `"added":["guests on site","kids on alpha"]`) {
		t.Errorf("audit row: %+v", last)
	}
	// Saving the same again changes nothing and isn't audited.
	before := len(ge.auditRows())
	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/notifications/protected-groups", gen.ProtectedGroupsInput{Entries: []protectedEntry{
		{Scope: "group", Id: ge.groupID, PiholeGroups: []string{"Guests"}},
		{Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{"kids"}},
	}}), http.StatusOK)
	if len(ge.auditRows()) != before {
		t.Error("an unchanged save was audited")
	}

	// A channel for the alerts.
	mustStatus(t, ge.admin.do(http.MethodPost, "/api/v1/notifications/channels", gen.ChannelInput{
		Kind: "discord", Name: "Alerts", Enabled: true, Events: []string{"protected_group_add"}, Secret: ptr(testHook),
	}), http.StatusCreated)

	protectedOf := func(from int) map[string][]any {
		_, details := ge.auditSince(from)
		out := map[string][]any{}
		rows := ge.auditRows()[from:]
		for i, d := range details {
			if rows[i].Action != "client_update" {
				continue
			}
			p, _ := d["protected_added"].([]any)
			out[rows[i].InstanceName] = p
		}
		return out
	}
	patch := func(path string, groups []int) {
		t.Helper()
		res := ge.admin.do(http.MethodPatch, path, gen.ClientUpdate{Client: "10.0.0.9", Groups: &groups})
		if res.Code != http.StatusOK {
			t.Fatalf("PATCH %s: %d %s", path, res.Code, res.Body)
		}
	}

	// Through the group, adding Kids: only alpha protects it.
	from := len(ge.auditRows())
	patch(ge.path("/clients"), []int{0, kids})
	p := protectedOf(from)
	if len(p) != 3 || len(p["alpha"]) != 1 || p["alpha"][0] != "Kids" || p["beta"] != nil || p["gamma"] != nil {
		t.Errorf("through the group, Kids: %v", p)
	}
	// Directly on beta, adding Guests: the mirrored group protects it there too.
	from = len(ge.auditRows())
	patch(ge.instPath("beta", "/clients"), []int{0, kids, guests})
	if p := protectedOf(from); len(p["beta"]) != 1 || p["beta"][0] != "Guests" {
		t.Errorf("directly on beta, Guests: %v", p)
	}
	// Taking a group away, or keeping one, isn't an addition.
	from = len(ge.auditRows())
	patch(ge.instPath("beta", "/clients"), []int{guests})
	if p := protectedOf(from); p["beta"] != nil {
		t.Errorf("a removal raised an alert: %v", p)
	}

	// The alerts reached the channel: alpha's Kids, and beta's Guests.
	waitReceived := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			found := slices.ContainsFunc(received, func(r string) bool { return strings.Contains(r, want) })
			mu.Unlock()
			if found {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("no message with %q; got %v", want, received)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitReceived(`added client `)
	waitReceived(`**Kids** on alpha`)
	waitReceived(`**Guests** on beta`)

	// Taking Kids off alpha tells the channel.
	mustStatus(t, ge.admin.do(http.MethodPut, "/api/v1/notifications/protected-groups", gen.ProtectedGroupsInput{Entries: []protectedEntry{
		{Scope: "group", Id: ge.groupID, PiholeGroups: []string{"guests"}},
	}}), http.StatusOK)
	waitReceived(`no more alerts when a client is added to kids on alpha`)

	// Deleting a group drops its protected groups with it.
	if res := ge.admin.do(http.MethodDelete, "/api/v1/instance-groups/"+strings.TrimPrefix(ge.target, "g-"), nil); res.Code != http.StatusNoContent {
		t.Fatalf("delete group: %d %s", res.Code, res.Body)
	}
	if got := decode[gen.ProtectedGroupSettings](t, ge.admin.do(http.MethodGet, "/api/v1/notifications/protected-groups", nil)); len(got.Entries) != 0 {
		t.Errorf("after deleting the group: %+v", got.Entries)
	}
}

func TestProtectedGroupRefusals(t *testing.T) {
	var mu sync.Mutex
	var received []string
	ge := newGroupEnv(t, withNotifications(t, &received, &mu))
	ge.addRoleUser("viewer", "viewer-password", rbac.ClientsEdit, rbac.InstancesManage)
	independent := decode[gen.InstanceGroup](t, ge.admin.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{
		Name: "labels", Mode: "independent", Members: []int64{ge.ids["alpha"]},
	})).Id
	put := func(c *client, entries []protectedEntry) response {
		return c.do(http.MethodPut, "/api/v1/notifications/protected-groups", gen.ProtectedGroupsInput{Entries: entries})
	}
	for _, tt := range []struct {
		entries []protectedEntry
		field   string
	}{
		{[]protectedEntry{{Scope: "everything", Id: 1, PiholeGroups: []string{"x"}}}, "scope"},
		{[]protectedEntry{{Scope: "instance", Id: 999, PiholeGroups: []string{"x"}}}, "id"},
		{[]protectedEntry{{Scope: "group", Id: independent, PiholeGroups: []string{"x"}}}, "id"},
		{[]protectedEntry{{Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{"a\nb"}}}, "pihole_groups"},
		{[]protectedEntry{{Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{strings.Repeat("g", 256)}}}, "pihole_groups"},
		{[]protectedEntry{{Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{"x"}}, {Scope: "instance", Id: ge.ids["alpha"], PiholeGroups: []string{"y"}}}, "entries"},
	} {
		res := put(ge.admin, tt.entries)
		var body gen.Error
		_ = decodeInto(res, &body)
		if res.Code != http.StatusBadRequest || body.Error.Details == nil || (*body.Error.Details)["field"] != tt.field {
			t.Errorf("%+v: %d %s", tt.entries, res.Code, res.Body)
		}
	}
	// instances.manage and clients.edit aren't enough.
	v := ge.loggedIn("viewer", "viewer-password")
	if res := v.do(http.MethodGet, "/api/v1/notifications/protected-groups", nil); res.Code != http.StatusForbidden {
		t.Errorf("GET without notifications.manage: %d", res.Code)
	}
	if res := put(v, nil); res.Code != http.StatusForbidden {
		t.Errorf("PUT without notifications.manage: %d", res.Code)
	}
}
