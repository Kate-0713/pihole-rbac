// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

// TestGroupWrites covers renaming and deleting Pi-hole groups against the fake, which answers as FTL does: a rename
// is a PUT on the old name carrying the new one, renaming a missing group changes nothing and succeeds, a taken name
// is refused, and a delete takes the group off everything, with Default recreated empty.
func TestGroupWrites(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		call  func(c *piholeapi.Client, kids int) error
		sent  string // the request the call makes, as Requests reports it
		check func(t *testing.T, ph *piholetest.Server, kids int, err error)
	}{
		{
			name: "rename keeps the ID and sets the comment and enabled flag",
			call: func(c *piholeapi.Client, _ int) error {
				return c.RenameGroup(ctx, "kids", piholeapi.Group{Name: "children", Comment: "after school", Enabled: false})
			},
			sent: "PUT /api/groups/kids",
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				g := group(t, ph, "children")
				if g.ID != kids || g.Comment != "after school" || g.Enabled {
					t.Errorf("renamed group %+v", g)
				}
				if hasGroup(ph, "kids") {
					t.Error("the old name is still there")
				}
			},
		},
		{
			name: "a name with a space is escaped in the path",
			call: func(c *piholeapi.Client, _ int) error {
				if err := c.RenameGroup(ctx, "kids", piholeapi.Group{Name: "school kids", Enabled: true}); err != nil {
					return err
				}
				return c.RenameGroup(ctx, "school kids", piholeapi.Group{Name: "kids", Enabled: true})
			},
			sent: "PUT /api/groups/school%20kids",
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil || group(t, ph, "kids").ID != kids {
					t.Errorf("err = %v, groups %+v", err, ph.Groups())
				}
			},
		},
		{
			name: "renaming a group that doesn't exist changes nothing and succeeds",
			call: func(c *piholeapi.Client, _ int) error {
				return c.RenameGroup(ctx, "nobody", piholeapi.Group{Name: "someone", Enabled: true})
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if hasGroup(ph, "someone") || len(ph.Groups()) != 3 {
					t.Errorf("groups %+v", ph.Groups())
				}
			},
		},
		{
			name: "renaming to a name that's taken is rejected",
			call: func(c *piholeapi.Client, _ int) error {
				return c.RenameGroup(ctx, "kids", piholeapi.Group{Name: "guests", Enabled: true})
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				var re *piholeapi.RejectedError
				if !errors.As(err, &re) {
					t.Fatalf("err = %v", err)
				}
				group(t, ph, "kids")
			},
		},
		{
			name: "a newline in the new name is rejected",
			call: func(c *piholeapi.Client, _ int) error {
				return c.RenameGroup(ctx, "kids", piholeapi.Group{Name: "a\nb", Enabled: true})
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				var re *piholeapi.RejectedError
				if !errors.As(err, &re) {
					t.Fatalf("err = %v", err)
				}
			},
		},
		{
			name: "renaming only the case is a rename",
			call: func(c *piholeapi.Client, _ int) error {
				return c.RenameGroup(ctx, "kids", piholeapi.Group{Name: "Kids", Enabled: true})
			},
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil || group(t, ph, "Kids").ID != kids || hasGroup(ph, "kids") {
					t.Errorf("err = %v, groups %+v", err, ph.Groups())
				}
			},
		},
		{
			name: "delete takes the group off every domain, client and list",
			call: func(c *piholeapi.Client, _ int) error { return c.DeleteGroup(ctx, "kids") },
			sent: "DELETE /api/groups/kids",
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if hasGroup(ph, "kids") {
					t.Error("the group is still there")
				}
				if g := ph.Domains()[0].Groups; !slices.Equal(g, []int{0}) {
					t.Errorf("domain groups %v", g)
				}
				if g := ph.Clients()[0].Groups; len(g) != 0 {
					t.Errorf("client groups %v (a client only in the deleted group is left in none)", g)
				}
				if g := ph.Lists()[0].Groups; !slices.Equal(g, []int{0}) {
					t.Errorf("list groups %v", g)
				}
			},
		},
		{
			name: "deleting a group that doesn't exist is a 404",
			call: func(c *piholeapi.Client, _ int) error { return c.DeleteGroup(ctx, "nobody") },
			check: func(t *testing.T, _ *piholetest.Server, _ int, err error) {
				var se *piholeapi.StatusError
				if !errors.As(err, &se) || se.Code != http.StatusNotFound {
					t.Errorf("err = %v", err)
				}
			},
		},
		{
			name: "Pi-hole lets Default be deleted, and recreates it empty",
			call: func(c *piholeapi.Client, _ int) error { return c.DeleteGroup(ctx, "Default") },
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if g := group(t, ph, "Default"); g.ID != 0 || g.Comment != "" || !g.Enabled {
					t.Errorf("Default after delete %+v", g)
				}
				if g := ph.Domains()[0].Groups; !slices.Equal(g, []int{kids}) {
					t.Errorf("domain groups %v: Default should be gone", g)
				}
			},
		},
		{
			name: "lists are read with their groups",
			call: func(c *piholeapi.Client, kids int) error {
				lists, err := c.ListLists(ctx)
				if err != nil {
					return err
				}
				if len(lists) != 1 || lists[0].Address != "https://lists.example/ads.txt" || lists[0].Type != "block" ||
					!slices.Equal(lists[0].Groups, []int{0, kids}) {
					t.Errorf("lists %+v", lists)
				}
				return nil
			},
			sent: "GET /api/lists",
			check: func(t *testing.T, _ *piholetest.Server, _ int, err error) {
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			kids := ph.AddGroup("kids")
			ph.AddGroup("guests")
			ph.AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Groups: []int{0, kids}, Enabled: true})
			ph.AddClient(piholetest.Client{Client: "10.0.0.5", Groups: []int{kids}})
			ph.AddList(piholetest.List{Address: "https://lists.example/ads.txt", Type: "block", Groups: []int{0, kids}, Enabled: true})
			c := newClient(t, ph.URL)
			err := tt.call(c, kids)
			if tt.sent != "" {
				if reqs := ph.Requests(); !slices.Contains(reqs, tt.sent) {
					t.Errorf("requests %v, want %q", reqs, tt.sent)
				}
			}
			tt.check(t, ph, kids, err)
		})
	}
}

func group(t *testing.T, ph *piholetest.Server, name string) piholetest.Group {
	t.Helper()
	groups := ph.Groups()
	i := slices.IndexFunc(groups, func(g piholetest.Group) bool { return g.Name == name })
	if i < 0 {
		t.Fatalf("no group %q in %+v", name, groups)
	}
	return groups[i]
}

func hasGroup(ph *piholetest.Server, name string) bool {
	return slices.ContainsFunc(ph.Groups(), func(g piholetest.Group) bool { return g.Name == name })
}
