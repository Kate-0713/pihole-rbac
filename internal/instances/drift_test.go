// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// driftEnv is three enabled instances on fake Pi-holes, alpha (the primary), beta and gamma, in a mirrored group.
type driftEnv struct {
	*svcEnv
	ph    map[string]*piholetest.Server
	ids   map[string]int64
	group Group
	drift *Drift
}

func newDriftEnv(t *testing.T) *driftEnv {
	t.Helper()
	e := newSvcEnv(t)
	de := &driftEnv{svcEnv: e, ph: map[string]*piholetest.Server{}, ids: map[string]int64{}}
	for _, n := range []string{"alpha", "beta", "gamma"} {
		env := "DRIFT_" + strings.ToUpper(n)
		e.pw.set(env, password)
		ph := piholetest.New(t, password)
		inst := e.create(n, env, ph.URL)
		if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
			t.Fatal(err)
		}
		de.ph[n], de.ids[n] = ph, inst.ID
	}
	de.group = e.createGroup(GroupInput{Name: "site", Mode: rbac.Mirrored, Primary: de.ids["alpha"],
		Members: []int64{de.ids["alpha"], de.ids["beta"], de.ids["gamma"]}})
	de.drift = &Drift{Service: e.svc, Now: func() time.Time { return t0 }}
	return de
}

func (de *driftEnv) check() Report {
	de.t.Helper()
	rep, err := de.drift.Check(de.ctx, de.group.ID)
	if err != nil {
		de.t.Fatal(err)
	}
	return rep
}

func TestDriftInSync(t *testing.T) {
	de := newDriftEnv(t)
	// The same entries everywhere, though the Pi-hole group IDs differ: groups are compared by name.
	for _, n := range []string{"beta", "alpha", "gamma"} {
		kids := de.ph[n].AddGroup("kids")
		de.ph[n].AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Groups: []int{kids}, Enabled: true})
		de.ph[n].AddClient(piholetest.Client{Client: "10.0.0.5", Groups: []int{0, kids}})
	}
	de.ph["beta"].AddGroup("padding")
	de.ph["beta"].Handle(func(http.ResponseWriter, *http.Request) bool { return false })
	rep := de.check()
	if !rep.PrimaryOK || !rep.CheckedAt.Equal(t0) || len(rep.Members) != 3 || !rep.Members[0].Primary {
		t.Fatalf("report %+v", rep)
	}
	// "padding" exists only on beta: a Pi-hole group the primary doesn't have.
	if len(rep.Domains)+len(rep.Clients) != 0 || len(rep.Groups) != 1 || rep.Groups[0].Difference != Extra || rep.Groups[0].Name != "padding" {
		t.Errorf("drift %+v %+v %+v", rep.Domains, rep.Clients, rep.Groups)
	}
	if got, ok := de.drift.Report(de.group.ID); !ok || !got.CheckedAt.Equal(t0) {
		t.Error("the report isn't kept")
	}
}

func TestDriftDifferences(t *testing.T) {
	de := newDriftEnv(t)
	kidsA := de.ph["alpha"].AddGroup("kids")
	de.ph["beta"].AddGroup("kids")
	de.ph["alpha"].AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Groups: []int{kidsA}, Enabled: true})
	de.ph["alpha"].AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: "tracker", Enabled: true})
	de.ph["alpha"].AddClient(piholetest.Client{Client: "10.0.0.5", Comment: "tv"})
	// beta: games.example in the Default group instead of kids, ads.example disabled, an extra regex, no client.
	de.ph["beta"].AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Enabled: true})
	de.ph["beta"].AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: "tracker", Enabled: false})
	de.ph["beta"].AddDomain(piholetest.Domain{Domain: "^bad", Type: "deny", Kind: "regex", Enabled: true})
	// gamma doesn't answer.
	de.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	})

	rep := de.check()
	if rep.Members[2].Name != "gamma" || rep.Members[2].Code != "pihole_status_error" || rep.Members[1].Code != "" {
		t.Errorf("members %+v", rep.Members)
	}
	type row struct {
		member, key string
		diff        Difference
	}
	var domains []row
	for _, d := range rep.Domains {
		domains = append(domains, row{d.MemberName, d.Domain + "/" + d.Kind, d.Difference})
	}
	want := []row{{"beta", "^bad/regex", Extra}, {"beta", "ads.example/exact", Changed}, {"beta", "games.example/exact", Changed}}
	if !slices.Equal(domains, want) {
		t.Errorf("domains %v, want %v", domains, want)
	}
	games := rep.Domains[2]
	if !slices.Equal(games.Primary.Groups, []string{"kids"}) || !slices.Equal(games.Other.Groups, []string{"Default"}) {
		t.Errorf("games.example groups %+v %+v", games.Primary, games.Other)
	}
	if ads := rep.Domains[1]; !ads.Primary.Enabled || ads.Other.Enabled {
		t.Errorf("ads.example %+v %+v", ads.Primary, ads.Other)
	}
	if len(rep.Clients) != 1 || rep.Clients[0].Difference != Missing || rep.Clients[0].MemberName != "beta" || rep.Clients[0].Primary.Comment != "tv" {
		t.Errorf("clients %+v", rep.Clients)
	}
	// kids exists on both, with the same settings: not drift. gamma's differences are unknown, not reported.
	if len(rep.Groups) != 0 {
		t.Errorf("groups %+v", rep.Groups)
	}
	if !rep.Drifted() || !rep.DomainsDrifted() || !rep.ClientsDrifted() {
		t.Error("not marked as drifted")
	}
}

func TestDriftPrimaryDown(t *testing.T) {
	de := newDriftEnv(t)
	de.ph["beta"].AddDomain(piholetest.Domain{Domain: "only-beta.example", Type: "deny", Kind: "exact", Enabled: true})
	de.ph["alpha"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	})
	rep := de.check()
	if rep.PrimaryOK || rep.Drifted() || rep.Members[0].Code == "" {
		t.Errorf("with the primary down: %+v", rep)
	}
}

func TestDriftGroupChanges(t *testing.T) {
	de := newDriftEnv(t)
	de.check()

	// A member disabled is left out; a primary disabled leaves nothing to compare with.
	if _, err := de.svc.SetEnabled(de.ctx, de.admin, de.ids["gamma"], false); err != nil {
		t.Fatal(err)
	}
	if rep := de.check(); len(rep.Members) != 2 {
		t.Errorf("members with gamma disabled %+v", rep.Members)
	}
	if _, err := de.svc.SetEnabled(de.ctx, de.admin, de.ids["alpha"], false); err != nil {
		t.Fatal(err)
	}
	if rep := de.check(); rep.PrimaryOK || len(rep.Members) != 1 {
		t.Errorf("with the primary disabled %+v", rep)
	}

	// A group that stops being mirrored, or is deleted, has no report.
	if _, err := de.svc.UpdateGroup(de.ctx, de.admin, de.group.ID, GroupInput{Name: "site", Mode: rbac.Independent, Members: de.group.Members}); err != nil {
		t.Fatal(err)
	}
	if _, err := de.drift.Check(de.ctx, de.group.ID); err == nil {
		t.Error("an independent group was checked")
	}
	if _, ok := de.drift.Report(de.group.ID); ok {
		t.Error("an independent group still has a report")
	}
}

func TestDriftRunAndPoke(t *testing.T) {
	de := newDriftEnv(t)
	de.drift.Interval, de.drift.Delay = time.Hour, time.Millisecond
	ctx, cancel := context.WithCancel(de.ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { de.drift.Run(ctx); close(done) }()

	// Run checks at once.
	waitFor(t, func() bool { _, ok := de.drift.Report(de.group.ID); return ok })
	before, _ := de.drift.Report(de.group.ID)
	if before.Drifted() {
		t.Fatal("drifted from the start")
	}
	// A poke checks again soon, and sees the change.
	de.ph["beta"].AddDomain(piholetest.Domain{Domain: "new.example", Type: "deny", Kind: "exact", Enabled: true})
	de.drift.Poke(de.group.ID)
	waitFor(t, func() bool { r, _ := de.drift.Report(de.group.ID); return r.Drifted() })
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
