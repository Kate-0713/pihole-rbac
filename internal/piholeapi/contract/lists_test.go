// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package contract_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// The gravity database's entries: domains, clients, Pi-hole groups and lists. Each is identified by its natural key
// (a domain with its type and kind, a client's identifier, a group's name, a list's address with its type), which
// is how the app matches them across Pi-holes.

func TestDomains(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	d := name(".example")
	t.Cleanup(func() {
		for _, typ := range []string{"allow", "deny"} {
			_ = c.DeleteDomain(ctx, d, typ, "exact")
		}
	})

	saved, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact", Comment: "first", Groups: []int{0}})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Domain != d || saved.Type != "deny" || saved.Kind != "exact" || !saved.Enabled || saved.Comment != "first" ||
		!slices.Equal(saved.Groups, []int{0}) {
		t.Errorf("added = %+v, want the entry, enabled, in the Default group only", saved)
	}

	t.Run("a duplicate is refused", func(t *testing.T) {
		_, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact"})
		wantRejected(t, err, alreadyPresent)
	})

	t.Run("the same domain can be on the allow list too", func(t *testing.T) {
		if _, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "allow", Kind: "exact"}); err != nil {
			t.Fatal(err)
		}
		if n := countDomains(t, c, d); n != 2 {
			t.Errorf("entries for %s = %d, want 2", d, n)
		}
	})

	t.Run("an exact entry that isn't a domain is refused", func(t *testing.T) {
		_, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: prefix + "not a domain", Type: "deny", Kind: "exact"})
		var re *piholeapi.RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a RejectedError", err)
		}
	})

	t.Run("update replaces comment, groups and enabled", func(t *testing.T) {
		got, err := c.UpdateDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact", Comment: "second", Groups: []int{0}})
		if err != nil {
			t.Fatal(err)
		}
		if got.Comment != "second" || got.Enabled {
			t.Errorf("updated = %+v, want comment second, disabled", got)
		}
		e := findDomain(t, c, d, "deny", "exact")
		if e == nil || e.Comment != "second" || e.Enabled {
			t.Errorf("read back = %+v, want comment second, disabled", e)
		}
	})

	t.Run("update is an upsert", func(t *testing.T) {
		other := name(".example")
		t.Cleanup(func() { _ = c.DeleteDomain(ctx, other, "deny", "regex") })
		if _, err := c.UpdateDomain(ctx, piholeapi.DomainEntry{Domain: other, Type: "deny", Kind: "regex", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if findDomain(t, c, other, "deny", "regex") == nil {
			t.Error("PUT on an entry that doesn't exist didn't create it")
		}
	})

	t.Run("delete, then delete again", func(t *testing.T) {
		if err := c.DeleteDomain(ctx, d, "allow", "exact"); err != nil {
			t.Fatal(err)
		}
		if findDomain(t, c, d, "allow", "exact") != nil {
			t.Error("still there after delete")
		}
		wantStatus(t, c.DeleteDomain(ctx, d, "allow", "exact"), http.StatusNotFound)
	})
}

func TestClients(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	g := addGroup(t, c)
	ip := "192.0.2.10" // documentation range: never a real client
	t.Cleanup(func() { _ = c.DeleteClient(ctx, ip) })

	saved, err := c.AddClient(ctx, ip, prefix+"first", []int{0, g.ID})
	if err != nil {
		t.Fatal(err)
	}
	if saved == nil || saved.Client != ip || !slices.Equal(sorted(saved.Groups), []int{0, g.ID}) {
		t.Errorf("added = %+v, want %s in groups 0 and %d", saved, ip, g.ID)
	}

	t.Run("a duplicate is refused", func(t *testing.T) {
		_, err := c.AddClient(ctx, ip, prefix, nil)
		wantRejected(t, err, alreadyPresent)
	})

	t.Run("update replaces the groups and comment", func(t *testing.T) {
		if _, err := c.UpdateClientGroups(ctx, ip, prefix+"second", []int{g.ID}); err != nil {
			t.Fatal(err)
		}
		e := findClient(t, c, ip)
		if e == nil || e.Comment != prefix+"second" || !slices.Equal(e.Groups, []int{g.ID}) {
			t.Errorf("read back = %+v, want comment %ssecond in group %d only", e, prefix, g.ID)
		}
	})

	t.Run("update is an upsert", func(t *testing.T) {
		other := "192.0.2.11"
		t.Cleanup(func() { _ = c.DeleteClient(ctx, other) })
		if _, err := c.UpdateClientGroups(ctx, other, prefix, []int{0}); err != nil {
			t.Fatal(err)
		}
		if findClient(t, c, other) == nil {
			t.Error("PUT on a client that doesn't exist didn't create it")
		}
	})

	t.Run("delete, then delete again", func(t *testing.T) {
		if err := c.DeleteClient(ctx, ip); err != nil {
			t.Fatal(err)
		}
		if findClient(t, c, ip) != nil {
			t.Error("still there after delete")
		}
		wantStatus(t, c.DeleteClient(ctx, ip), http.StatusNotFound)
	})
}

func TestGroups(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	g := addGroup(t, c)
	t.Cleanup(func() { _ = c.DeleteGroup(ctx, g.Name) }) // by its name at the end, after the rename below

	t.Run("a duplicate name is refused", func(t *testing.T) {
		wantRejected(t, c.AddGroup(ctx, piholeapi.Group{Name: g.Name, Enabled: true}), alreadyPresent)
	})

	t.Run("update sets comment and enabled", func(t *testing.T) {
		if err := c.UpdateGroup(ctx, piholeapi.Group{Name: g.Name, Comment: "off", Enabled: false}); err != nil {
			t.Fatal(err)
		}
		got := findGroup(t, c, g.Name)
		if got == nil || got.Comment != "off" || got.Enabled {
			t.Errorf("read back = %+v, want comment off, disabled", got)
		}
	})

	t.Run("update is an upsert", func(t *testing.T) {
		other := name("")
		t.Cleanup(func() { _ = c.DeleteGroup(ctx, other) })
		if err := c.UpdateGroup(ctx, piholeapi.Group{Name: other, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if findGroup(t, c, other) == nil {
			t.Error("PUT on a group that doesn't exist didn't create it")
		}
	})

	t.Run("rename keeps the ID", func(t *testing.T) {
		renamed := name("")
		if err := c.RenameGroup(ctx, g.Name, piholeapi.Group{Name: renamed, Comment: "renamed", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		got := findGroup(t, c, renamed)
		if got == nil || got.ID != g.ID || got.Comment != "renamed" || !got.Enabled {
			t.Errorf("renamed = %+v, want ID %d, comment renamed, enabled", got, g.ID)
		}
		if findGroup(t, c, g.Name) != nil {
			t.Error("the old name is still there")
		}
		g.Name = renamed
	})

	t.Run("rename onto a name that's taken is refused", func(t *testing.T) {
		taken := addGroup(t, c)
		wantRejected(t, c.RenameGroup(ctx, g.Name, piholeapi.Group{Name: taken.Name, Enabled: true}), alreadyPresent)
	})

	t.Run("rename of a group that doesn't exist is refused", func(t *testing.T) {
		missing, to := name(""), name("")
		t.Cleanup(func() { _ = c.DeleteGroup(ctx, to) })
		wantRejected(t, c.RenameGroup(ctx, missing, piholeapi.Group{Name: to, Enabled: true}), "Group not found")
		if findGroup(t, c, missing) != nil || findGroup(t, c, to) != nil {
			t.Error("a group was created")
		}
	})

	t.Run("delete takes the group off its members, then delete again", func(t *testing.T) {
		d := name(".example")
		t.Cleanup(func() { _ = c.DeleteDomain(ctx, d, "deny", "exact") })
		if _, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact", Groups: []int{0, g.ID}}); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteGroup(ctx, g.Name); err != nil {
			t.Fatal(err)
		}
		if findGroup(t, c, g.Name) != nil {
			t.Error("still there after delete")
		}
		if e := findDomain(t, c, d, "deny", "exact"); e == nil || !slices.Equal(e.Groups, []int{0}) {
			t.Errorf("domain after the delete = %+v, want groups [0]", e)
		}
		wantStatus(t, c.DeleteGroup(ctx, g.Name), http.StatusNotFound)
	})
}

// The Default group isn't protected: deleting it is allowed, strips it from everything, and Pi-hole recreates it
// empty, with no comment. The app refuses the delete itself.
func TestDefaultGroupDeletable(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	g := addGroup(t, c)
	d := name(".example")
	t.Cleanup(func() { _ = c.DeleteDomain(ctx, d, "deny", "exact") })
	if _, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: d, Type: "deny", Kind: "exact", Groups: []int{0, g.ID}}); err != nil {
		t.Fatal(err)
	}

	if err := c.DeleteGroup(ctx, "Default"); err != nil {
		t.Fatalf("deleting Default: %v", err)
	}
	def := findGroup(t, c, "Default")
	if def == nil || def.ID != 0 || def.Comment != "" || !def.Enabled {
		t.Errorf("Default afterwards = %+v, want ID 0 again, enabled, no comment", def)
	}
	if e := findDomain(t, c, d, "deny", "exact"); e == nil || !slices.Equal(e.Groups, []int{g.ID}) {
		t.Errorf("domain afterwards = %+v, want only group %d", e, g.ID)
	}
}

func TestLists(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	addr := "http://127.0.0.1:9/" + name(".txt") // nothing listens on the discard port; never downloaded here
	t.Cleanup(func() {
		for _, typ := range []string{"block", "allow"} {
			_ = c.DeleteList(ctx, addr, typ)
		}
	})

	saved, err := c.AddList(ctx, piholeapi.ListEntry{Address: addr, Type: "block", Comment: "first", Enabled: true, Groups: []int{0}})
	if err != nil {
		t.Fatal(err)
	}
	if saved.Address != addr || saved.Type != "block" || !saved.Enabled || saved.Comment != "first" ||
		!slices.Equal(saved.Groups, []int{0}) || saved.Status != piholeapi.ListStatusNever {
		t.Errorf("added = %+v, want the list, enabled, in the Default group, never downloaded", saved)
	}

	t.Run("a duplicate address of the same type is refused", func(t *testing.T) {
		_, err := c.AddList(ctx, piholeapi.ListEntry{Address: addr, Type: "block", Enabled: true})
		wantRejected(t, err, alreadyPresent)
	})

	t.Run("the same address can be an allow list too", func(t *testing.T) {
		if _, err := c.AddList(ctx, piholeapi.ListEntry{Address: addr, Type: "allow", Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if findList(t, c, addr, "allow") == nil || findList(t, c, addr, "block") == nil {
			t.Error("want both an allow and a block list for the address")
		}
	})

	t.Run("an address with a space is refused", func(t *testing.T) {
		_, err := c.AddList(ctx, piholeapi.ListEntry{Address: "http://127.0.0.1:9/" + prefix + "a b", Type: "block", Enabled: true})
		var re *piholeapi.RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a RejectedError", err)
		}
	})

	t.Run("update replaces comment, groups and enabled", func(t *testing.T) {
		if _, err := c.UpdateList(ctx, piholeapi.ListEntry{Address: addr, Type: "block", Comment: "second", Groups: []int{0}}); err != nil {
			t.Fatal(err)
		}
		l := findList(t, c, addr, "block")
		if l == nil || l.Comment != "second" || l.Enabled {
			t.Errorf("read back = %+v, want comment second, disabled", l)
		}
	})

	t.Run("update is an upsert", func(t *testing.T) {
		other := "http://127.0.0.1:9/" + name(".txt")
		t.Cleanup(func() { _ = c.DeleteList(ctx, other, "block") })
		if _, err := c.UpdateList(ctx, piholeapi.ListEntry{Address: other, Type: "block", Enabled: true, Groups: []int{0}}); err != nil {
			t.Fatal(err)
		}
		if findList(t, c, other, "block") == nil {
			t.Error("PUT on a list that doesn't exist didn't create it")
		}
	})

	t.Run("delete, then delete again", func(t *testing.T) {
		if err := c.DeleteList(ctx, addr, "allow"); err != nil {
			t.Fatal(err)
		}
		if findList(t, c, addr, "allow") != nil {
			t.Error("still there after delete")
		}
		wantStatus(t, c.DeleteList(ctx, addr, "allow"), http.StatusNotFound)
	})
}

// addGroup adds a Pi-hole group with a new name, deleted when the test ends, and returns it as read back.
func addGroup(t *testing.T, c *piholeapi.Client) piholeapi.Group {
	t.Helper()
	ctx := context.Background()
	n := name("")
	if err := c.AddGroup(ctx, piholeapi.Group{Name: n, Comment: prefix, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteGroup(ctx, n) })
	g := findGroup(t, c, n)
	if g == nil {
		t.Fatalf("group %s not there after adding it", n)
	}
	return *g
}

func findDomain(t *testing.T, c *piholeapi.Client, domain, typ, kind string) *piholeapi.DomainEntry {
	t.Helper()
	all, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range all {
		if d.Domain == domain && d.Type == typ && d.Kind == kind {
			return &d
		}
	}
	return nil
}

func countDomains(t *testing.T, c *piholeapi.Client, domain string) int {
	t.Helper()
	all, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range all {
		if d.Domain == domain {
			n++
		}
	}
	return n
}

func findClient(t *testing.T, c *piholeapi.Client, id string) *piholeapi.ClientEntry {
	t.Helper()
	all, err := c.ListClients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if e.Client == id {
			return &e
		}
	}
	return nil
}

func findGroup(t *testing.T, c *piholeapi.Client, n string) *piholeapi.Group {
	t.Helper()
	all, err := c.ListGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range all {
		if g.Name == n {
			return &g
		}
	}
	return nil
}

func findList(t *testing.T, c *piholeapi.Client, addr, typ string) *piholeapi.ListEntry {
	t.Helper()
	all, err := c.ListLists(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range all {
		if l.Address == addr && l.Type == typ {
			return &l
		}
	}
	return nil
}

// alreadyPresent is in FTL's message when a gravity database write breaks a UNIQUE constraint.
const alreadyPresent = "The item is already present"

// wantRejected checks err is a *RejectedError whose message contains msg. FTL v6.9 refuses a write whose every item
// failed with a 400 database_error, the reason in its hint, rather than a 2xx listing the item under
// processed.errors, which the app writes one item at a time never sees.
func wantRejected(t *testing.T, err error, msg string) {
	t.Helper()
	var re *piholeapi.RejectedError
	if !errors.As(err, &re) || !strings.Contains(re.Message, msg) {
		t.Errorf("err = %v, want a RejectedError saying %q", err, msg)
	}
}

// wantStatus checks err is a *StatusError with code.
func wantStatus(t *testing.T, err error, code int) {
	t.Helper()
	var se *piholeapi.StatusError
	if !errors.As(err, &se) || se.Code != code {
		t.Errorf("err = %v, want a StatusError %d", err, code)
	}
}

func sorted(s []int) []int {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}
