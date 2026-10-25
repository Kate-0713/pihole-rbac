// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

// fill gives alpha (the primary) a kids group, three entries (one disabled) and a client; beta has some of it, wrong
// in places, and things of its own.
func (de *driftEnv) fill() {
	a, b := de.ph["alpha"], de.ph["beta"]
	kidsA := a.AddGroup("kids")
	a.AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: "tracker", Enabled: true})
	a.AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Groups: []int{kidsA}, Enabled: true})
	a.AddDomain(piholetest.Domain{Domain: "off.example", Type: "deny", Kind: "exact", Enabled: false})
	a.AddClient(piholetest.Client{Client: "10.0.1.5", Comment: "printer", Groups: []int{kidsA}})

	b.AddGroup("beta-only")
	b.AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: "old", Enabled: true})
	b.AddDomain(piholetest.Domain{Domain: "^extra", Type: "deny", Kind: "regex", Enabled: true})
	b.AddClient(piholetest.Client{Client: "10.9.9.9"})
}

func TestReconcileAll(t *testing.T) {
	de := newDriftEnv(t)
	de.fill()
	res, err := de.drift.Reconcile(de.ctx, de.group.ID, Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		if it.Err != nil {
			t.Errorf("%s %s on %s: %v", it.Action, it.Kind, it.MemberName, it.Err)
		}
	}
	// Everything matches the primary now, but beta's own Pi-hole group is kept.
	rep := de.check()
	if len(rep.Domains)+len(rep.Clients) != 0 {
		t.Errorf("still differs: %+v %+v", rep.Domains, rep.Clients)
	}
	if len(rep.Groups) != 1 || rep.Groups[0].Name != "beta-only" || rep.Groups[0].Difference != Extra {
		t.Errorf("groups %+v", rep.Groups)
	}
	// The disabled entry was copied disabled; games.example is in beta's own kids group.
	for _, d := range de.ph["beta"].Domains() {
		if d.Domain == "off.example" && d.Enabled {
			t.Error("off.example was copied enabled")
		}
	}
	// gamma, which had none of the primary's items, was brought in line too: "all" covers every enabled member.
	if rep.Members[2].Code != "" || len(de.ph["gamma"].Domains()) != 3 {
		t.Errorf("gamma %+v", rep.Members[2])
	}
	var actions []string
	for _, it := range res.Items {
		if it.MemberName == "beta" {
			actions = append(actions, string(it.Kind)+":"+string(it.Action))
		}
	}
	slices.Sort(actions)
	// kids added; ads.example changed, games.example and off.example added, ^extra deleted; the printer added and
	// 10.9.9.9 deleted.
	want := []string{"client:add", "client:delete", "domain:add", "domain:add", "domain:delete", "domain:update", "group:add"}
	if !slices.Equal(actions, want) {
		t.Errorf("beta's actions %v, want %v", actions, want)
	}
}

func TestReconcileItems(t *testing.T) {
	de := newDriftEnv(t)
	de.fill()
	b := de.ids["beta"]
	res, err := de.drift.Reconcile(de.ctx, de.group.ID, Selection{
		Domains: []DomainKey{
			{Member: b, Domain: "games.example", Type: "deny", Kind: "exact"}, // needs kids, which beta doesn't have
			{Member: b, Domain: "same.example", Type: "deny", Kind: "exact"},  // not different: nothing to do
		},
		Groups: []GroupKey{{Member: b, Name: "beta-only"}}, // only on beta: never deleted
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range res.Items {
		s := string(it.Kind) + ":" + string(it.Action)
		if it.Err != nil {
			s += ":error"
		}
		got = append(got, s)
	}
	slices.Sort(got)
	want := []string{"domain:add", "domain:none", "group:add", "group:none:error"}
	if !slices.Equal(got, want) {
		t.Errorf("items %v, want %v", got, want)
	}
	if !slices.ContainsFunc(res.Items, func(it ReconcileItem) bool { return errors.Is(it.Err, ErrNotReconcilable) }) {
		t.Error("the beta-only group's refusal isn't ErrNotReconcilable")
	}
	// Only beta was touched; gamma, which differs too, wasn't named.
	if len(res.Members) != 1 || res.Members[0].Name != "beta" || len(de.ph["gamma"].Domains()) != 0 {
		t.Errorf("members %+v, gamma %+v", res.Members, de.ph["gamma"].Domains())
	}
	// The rest of beta is as it was.
	rep := de.check()
	var left []string
	for _, d := range rep.Domains {
		if d.MemberName == "beta" {
			left = append(left, d.Domain)
		}
	}
	slices.Sort(left)
	if !slices.Equal(left, []string{"^extra", "ads.example", "off.example"}) {
		t.Errorf("beta still differs in %v", left)
	}
}

func TestReconcileFailures(t *testing.T) {
	de := newDriftEnv(t)
	de.fill()
	broken := func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusInternalServerError)
		return true
	}

	// A member that can't be read is left alone and reported.
	de.ph["gamma"].Handle(broken)
	res, err := de.drift.Reconcile(de.ctx, de.group.ID, Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Members[1].Name != "gamma" || res.Members[1].Code != "pihole_status_error" || res.Members[0].Code != "" {
		t.Errorf("members %+v", res.Members)
	}

	// A write a member refuses is that item's failure; the others go ahead.
	de.ph["gamma"].Handle(func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && r.URL.Path == "/api/clients" {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		return false
	})
	res, err = de.drift.Reconcile(de.ctx, de.group.ID, Selection{All: true})
	if err != nil {
		t.Fatal(err)
	}
	var failed, ok int
	for _, it := range res.Items {
		if it.MemberName != "gamma" {
			continue
		}
		if it.Err != nil {
			failed++
			if it.Kind != ItemClient {
				t.Errorf("unexpected failure %+v", it)
			}
		} else {
			ok++
		}
	}
	if failed != 1 || ok == 0 {
		t.Errorf("gamma: %d failed, %d ok", failed, ok)
	}

	// Without the primary nothing is changed.
	de.ph["alpha"].Handle(broken)
	writes := len(de.ph["beta"].Requests())
	_, err = de.drift.Reconcile(de.ctx, de.group.ID, Selection{All: true})
	var pe *PrimaryError
	if !errors.As(err, &pe) || pe.Name != "alpha" {
		t.Errorf("with the primary down: %v", err)
	}
	if len(de.ph["beta"].Requests()) != writes {
		t.Error("beta was asked without the primary")
	}
}
