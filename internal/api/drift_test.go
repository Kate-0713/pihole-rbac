// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func (ge *groupEnv) withDrift() *instances.Drift {
	d := &instances.Drift{Service: ge.srv.Instances, Delay: time.Millisecond, Interval: time.Hour}
	ge.srv.Drift = d
	return d
}

func (ge *groupEnv) driftPath(suffix string) string {
	return "/api/v1/instance-groups/" + strconv.FormatInt(ge.groupID, 10) + "/drift" + suffix
}

// userWith makes a user holding perms on the group alone, and logs them in.
func (ge *groupEnv) userWith(name string, perms ...rbac.Permission) *client {
	ge.t.Helper()
	var grants []gen.Grant
	for _, p := range perms {
		grants = append(grants, gen.Grant{Permission: string(p), Scope: "group", Id: ptr(ge.groupID)})
	}
	res := ge.admin.do(http.MethodPost, "/api/v1/roles", gen.RoleCreate{Name: name + " role", Grants: &grants})
	mustStatus(ge.t, res, http.StatusCreated)
	role := decode[gen.Role](ge.t, res).Id
	mustStatus(ge.t, ge.admin.do(http.MethodPost, "/api/v1/users", gen.UserCreate{Username: name, Password: name + "-password-12", RoleIds: []int64{role}}), http.StatusCreated)
	return ge.loggedIn(name, name+"-password-12")
}

func TestGroupDrift(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()

	// Before any check.
	rep := decode[gen.DriftReport](t, ge.admin.do(http.MethodGet, ge.driftPath(""), nil))
	if rep.State != "not_checked" || rep.CheckedAt != nil || rep.Group != "site" || len(rep.Members) != 0 {
		t.Fatalf("before a check: %+v", rep)
	}
	if tl := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)); tl.Targets[3].Drifted != nil {
		t.Error("drifted before a check")
	}

	// In sync.
	rep = decode[gen.DriftReport](t, ge.admin.do(http.MethodPost, ge.driftPath("/check"), nil))
	if rep.State != "checked" || rep.Drifted || rep.CheckedAt == nil || len(rep.Members) != 3 || !rep.Members[0].Primary {
		t.Fatalf("in sync: %+v", rep)
	}

	// beta gets an entry and a client of its own; gamma stops answering.
	ge.ph["beta"].AddDomain(piholetest.Domain{Domain: "beta-only.example", Type: "deny", Kind: "exact", Enabled: true})
	ge.ph["alpha"].AddClient(piholetest.Client{Client: "10.0.0.5"})
	ge.down("gamma")
	rep = decode[gen.DriftReport](t, ge.admin.do(http.MethodPost, ge.driftPath("/check"), nil))
	if !rep.Drifted || rep.Counts.Domains != 1 || rep.Counts.Clients != 1 || rep.Domains == nil || rep.Clients == nil {
		t.Fatalf("drifted: %+v", rep)
	}
	d := (*rep.Domains)[0]
	if d.Instance != "beta" || d.Difference != "extra" || d.Member == nil || d.Primary != nil || d.Domain != "beta-only.example" {
		t.Errorf("domain drift %+v", d)
	}
	if c := (*rep.Clients)[0]; c.Difference != "missing" || c.Instance != "beta" || c.Primary == nil {
		t.Errorf("client drift %+v", c)
	}
	if m := rep.Members[2]; m.Status != "failed" || m.Error == nil || m.Error.Code != "pihole_status_error" {
		t.Errorf("gamma %+v", m)
	}
	// GET gives the same report.
	if got := decode[gen.DriftReport](t, ge.admin.do(http.MethodGet, ge.driftPath(""), nil)); !got.Drifted || !got.CheckedAt.Equal(*rep.CheckedAt) {
		t.Errorf("GET %+v", got)
	}

	// The badges.
	if tl := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)); tl.Targets[3].Drifted == nil || !*tl.Targets[3].Drifted {
		t.Errorf("target %+v", tl.Targets[3])
	}
	if dl := decode[gen.DomainList](t, ge.admin.do(http.MethodGet, ge.path("/domains"), nil)); dl.Drifted == nil || !*dl.Drifted {
		t.Errorf("domain list drifted %v", dl.Drifted)
	}
	if cl := decode[gen.ClientList](t, ge.admin.do(http.MethodGet, ge.path("/clients"), nil)); cl.Drifted == nil || !*cl.Drifted {
		t.Errorf("client list drifted %v", cl.Drifted)
	}
	if dl := decode[gen.DomainList](t, ge.admin.do(http.MethodGet, ge.instPath("beta", "/domains"), nil)); dl.Drifted != nil {
		t.Error("an instance's list carries drifted")
	}

	t.Run("the primary down", func(t *testing.T) {
		ge.down("alpha")
		rep := decode[gen.DriftReport](t, ge.admin.do(http.MethodPost, ge.driftPath("/check"), nil))
		if rep.State != "primary_unavailable" || rep.Drifted {
			t.Errorf("%+v", rep)
		}
		if tl := decode[gen.TargetList](t, ge.admin.do(http.MethodGet, "/api/v1/targets", nil)); tl.Targets[3].Drifted != nil {
			t.Error("drifted is given when nothing could be compared")
		}
	})
}

func TestGroupDriftPermissions(t *testing.T) {
	ge := newGroupEnv(t)
	ge.withDrift()
	ge.ph["beta"].AddDomain(piholetest.Domain{Domain: "beta-only.example", Type: "deny", Kind: "exact", Enabled: true})
	ge.ph["beta"].AddClient(piholetest.Client{Client: "10.0.0.9"})
	ge.ph["beta"].AddGroup("beta-group")
	mustStatus(t, ge.admin.do(http.MethodPost, ge.driftPath("/check"), nil), http.StatusOK)

	// drift.view alone: the counts and the Pi-hole groups, no entries.
	watcher := ge.userWith("watcher", rbac.DriftView)
	rep := decode[gen.DriftReport](t, watcher.do(http.MethodGet, ge.driftPath(""), nil))
	if rep.Counts.Domains != 1 || rep.Counts.Clients != 1 || rep.Domains != nil || rep.Clients != nil || rep.Groups == nil || len(*rep.Groups) != 1 {
		t.Errorf("drift.view alone: %+v", rep)
	}
	// With domains.view too, the domain entries.
	editor := ge.userWith("editor", rbac.DriftView, rbac.DomainsView)
	rep = decode[gen.DriftReport](t, editor.do(http.MethodGet, ge.driftPath(""), nil))
	if rep.Domains == nil || len(*rep.Domains) != 1 || rep.Clients != nil {
		t.Errorf("with domains.view: %+v", rep)
	}
	// Without drift.view, even with every view permission: 403. So is a group that doesn't exist.
	viewer := ge.userWith("viewer", rbac.DomainsView, rbac.ClientsView)
	for _, c := range []*client{viewer} {
		if res := c.do(http.MethodGet, ge.driftPath(""), nil); res.Code != http.StatusForbidden || errorDetails(t, res)["permission"] != "drift.view" {
			t.Errorf("without drift.view: %d %s", res.Code, res.Body)
		}
		if res := c.do(http.MethodPost, ge.driftPath("/check"), nil); res.Code != http.StatusForbidden {
			t.Errorf("check without drift.view: %d", res.Code)
		}
	}
	if res := ge.admin.do(http.MethodGet, "/api/v1/instance-groups/999/drift", nil); res.Code != http.StatusForbidden {
		t.Errorf("a missing group: %d", res.Code)
	}
	// An independent group isn't checked: it has nothing to mirror.
	res := ge.admin.do(http.MethodPost, "/api/v1/instance-groups", gen.InstanceGroupInput{Name: "labels", Mode: "independent", Members: []int64{ge.ids["beta"]}})
	mustStatus(t, res, http.StatusCreated)
	if res := ge.admin.do(http.MethodGet, "/api/v1/instance-groups/"+strconv.FormatInt(decode[gen.InstanceGroup](t, res).Id, 10)+"/drift", nil); res.Code != http.StatusForbidden {
		t.Errorf("an independent group: %d", res.Code)
	}
}

// TestGroupDriftFollowsWrites: a write through the group, or to one member, gets the group checked again soon.
func TestGroupDriftFollowsWrites(t *testing.T) {
	ge := newGroupEnv(t)
	d := ge.withDrift()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitUntil(t, func() bool { r, ok := d.Report(ge.groupID); return ok && !r.Drifted() })

	// gamma fails, so the entry reaches only alpha and beta, and the group drifts.
	ge.down("gamma")
	res := ge.admin.do(http.MethodPost, ge.path("/domains"), gen.DomainInput{Domain: "games.example", Type: "deny", Kind: "exact"})
	mustStatus(t, res, http.StatusMultiStatus)
	ge.ph["gamma"].Handle(func(http.ResponseWriter, *http.Request) bool { return false })
	waitUntil(t, func() bool { r, _ := d.Report(ge.groupID); return r.Drifted() })

	// A retry on gamma brings it back in line.
	res = ge.admin.do(http.MethodPost, ge.path("/domains?members="+strconv.FormatInt(ge.ids["gamma"], 10)), gen.DomainInput{Domain: "games.example", Type: "deny", Kind: "exact"})
	mustStatus(t, res, http.StatusOK)
	waitUntil(t, func() bool { r, _ := d.Report(ge.groupID); return !r.Drifted() })

	// A change to beta alone makes it drift again.
	res = ge.admin.do(http.MethodPatch, ge.instPath("beta", "/domains"), gen.DomainUpdate{Domain: "games.example", Type: "deny", Kind: "exact", Comment: ptr("beta only")})
	mustStatus(t, res, http.StatusOK)
	waitUntil(t, func() bool { r, _ := d.Report(ge.groupID); return r.Drifted() })
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
