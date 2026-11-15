// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/lists"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

const (
	adsList    = "https://lists.example/ads.txt"
	kidsList   = "https://lists.example/kids.txt"
	secretList = "https://user:secret@lists.example/private.txt"
)

// fillLists gives alpha (the primary) three lists: ads, a disabled kids list in its kids group, and one with a
// password in its address. beta has ads with another comment and the kids list enabled, plus a list of its own;
// gamma has nothing.
func (de *driftEnv) fillLists() {
	a, b := de.ph["alpha"], de.ph["beta"]
	kidsA := a.AddGroup("kids")
	kidsB := b.AddGroup("kids")
	a.AddList(piholetest.List{Address: adsList, Type: "block", Comment: "ads", Enabled: true, Status: 1, Number: 5000})
	a.AddList(piholetest.List{Address: kidsList, Type: "block", Groups: []int{kidsA}, Enabled: false})
	a.AddList(piholetest.List{Address: secretList, Type: "allow", Enabled: true})

	b.AddList(piholetest.List{Address: adsList, Type: "block", Comment: "old", Enabled: true, Status: 4})
	b.AddList(piholetest.List{Address: kidsList, Type: "block", Groups: []int{kidsB}, Enabled: true})
	b.AddList(piholetest.List{Address: adsList, Type: "allow", Enabled: true}) // the same address as the other type
}

func TestDriftLists(t *testing.T) {
	de := newDriftEnv(t)
	de.fillLists()
	rep := de.check()
	type row struct {
		member, address, typ string
		diff                 Difference
	}
	var got []row
	for _, l := range rep.Lists {
		got = append(got, row{l.MemberName, l.Address, l.Type, l.Difference})
	}
	// Status and counts differ between alpha and beta for the ads list, but only the comment counts as drift.
	want := []row{
		{"beta", adsList, "allow", Extra}, {"beta", adsList, "block", Changed}, {"beta", kidsList, "block", Changed},
		{"beta", secretList, "allow", Missing},
		{"gamma", adsList, "block", Missing}, {"gamma", kidsList, "block", Missing}, {"gamma", secretList, "allow", Missing},
	}
	if !slices.Equal(got, want) {
		t.Errorf("lists %v\nwant %v", got, want)
	}
	kids := rep.Lists[2]
	if !slices.Equal(kids.Primary.Groups, []string{"kids"}) || kids.Primary.Enabled || !kids.Other.Enabled {
		t.Errorf("kids list %+v %+v", kids.Primary, kids.Other)
	}
	if !rep.ListsDrifted() || !rep.Drifted() || rep.DomainsDrifted() {
		t.Error("flags wrong")
	}
}

func TestReconcileLists(t *testing.T) {
	de := newDriftEnv(t)
	de.fillLists()
	var mu sync.Mutex
	checked := []string{}
	check := func(address string) error { // called for every member at once
		mu.Lock()
		defer mu.Unlock()
		checked = append(checked, address)
		return lists.CheckAddress(address, false)
	}
	res, err := de.drift.Reconcile(de.ctx, de.group.ID, Selection{All: true, CheckList: check})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		member, key string
		action      Action
		gravity     bool
		failed      bool
	}
	var got []row
	for _, it := range res.Items {
		if it.Kind != ItemList {
			continue
		}
		got = append(got, row{it.MemberName, it.List.Type + " " + it.List.Address, it.Action, it.NeedsGravity, it.Err != nil})
	}
	slices.SortFunc(got, func(a, b row) int {
		if a.member+a.key < b.member+b.key {
			return -1
		}
		return 1
	})
	want := []row{
		{"beta", "allow " + adsList, ActionDelete, false, false},
		{"beta", "allow " + secretList, ActionAdd, false, true}, // refused by the address check, never sent
		{"beta", "block " + adsList, ActionUpdate, false, false},
		{"beta", "block " + kidsList, ActionUpdate, false, false}, // disabled, so nothing waits for gravity
		{"gamma", "allow " + secretList, ActionAdd, false, true},
		{"gamma", "block " + adsList, ActionAdd, true, false},
		{"gamma", "block " + kidsList, ActionAdd, false, false}, // added disabled
	}
	if !slices.Equal(got, want) {
		t.Errorf("list items\n%v\nwant\n%v", got, want)
	}
	for _, it := range res.Items {
		var ae *lists.AddressError
		if it.Kind == ItemList && it.Err != nil && !errors.As(it.Err, &ae) {
			t.Errorf("%s failed with %v, want an AddressError", it.List.Address, it.Err)
		}
	}
	// gamma's kids list needed the kids group, which reconcile created there first (groups go first anyway).
	g := de.ph["gamma"]
	if i := slices.IndexFunc(g.Lists(), func(l piholetest.List) bool { return l.Address == kidsList }); i < 0 || g.Lists()[i].Enabled {
		t.Errorf("gamma's lists %+v", g.Lists())
	}
	if n := len(de.ph["beta"].Lists()); n != 2 {
		t.Errorf("beta has %d lists, want 2 (the extra one deleted, the secret one not added)", n)
	}
	// What's left is the list reconcile wouldn't copy.
	rep := de.check()
	for _, ld := range rep.Lists {
		if ld.Address != secretList {
			t.Errorf("still differs: %+v", ld)
		}
	}
	// Only lists being added are checked: changing or deleting an existing one never is.
	slices.Sort(checked)
	if want := []string{adsList, kidsList, secretList, secretList}; !slices.Equal(checked, want) {
		t.Errorf("checked %v, want %v", checked, want)
	}
}

// A list is selected by its address as the API shows it (redacted) as well as by the real one, and a selected list
// that already matches is reported unchanged.
func TestReconcileListItems(t *testing.T) {
	de := newDriftEnv(t)
	de.fillLists()
	b, g := de.ids["beta"], de.ids["gamma"]
	res, err := de.drift.Reconcile(de.ctx, de.group.ID, Selection{Lists: []ListKey{
		{Member: g, Address: lists.Redacted(secretList), Type: "allow"},
		{Member: b, Address: "https://lists.example/same.txt", Type: "block"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, it := range res.Items {
		got = append(got, it.MemberName+" "+string(it.Kind)+":"+string(it.Action))
	}
	slices.Sort(got)
	if want := []string{"beta list:none", "gamma list:add"}; !slices.Equal(got, want) {
		t.Errorf("items %v, want %v", got, want)
	}
	gl := de.ph["gamma"].Lists()
	if len(gl) != 1 || gl[0].Address != secretList {
		t.Errorf("gamma's lists %+v: the real address should have been copied", gl)
	}
	if len(de.ph["beta"].Lists()) != 3 {
		t.Error("beta was changed")
	}
}
