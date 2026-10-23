// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestCatalogueWellFormed(t *testing.T) {
	name := regexp.MustCompile(`^[a-z]+\.[a-z]+$`)
	seen := map[Permission]bool{}
	for _, p := range Catalogue() {
		if seen[p.Name] {
			t.Errorf("%s is in the catalogue twice", p.Name)
		}
		seen[p.Name] = true
		if !name.MatchString(string(p.Name)) {
			t.Errorf("%q isn't of the form area.action", p.Name)
		}
		if p.Class < ClassInstance || p.Class > ClassGlobal {
			t.Errorf("%s has no class", p.Name)
		}
		if p.Description == "" {
			t.Errorf("%s has no description", p.Name)
		}
		if got, ok := Lookup(string(p.Name)); !ok || got != p {
			t.Errorf("Lookup(%s) = %v, %v", p.Name, got, ok)
		}
	}
	if _, ok := Lookup("domains.delete"); ok {
		t.Error("Lookup found a permission that isn't in the catalogue")
	}
}

// The builtin admin role is created by the first migration with every permission at scope all. A permission added to
// the catalogue without a migration granting it to admin (or the reverse) fails here.
func TestCatalogueMatchesBuiltinAdmin(t *testing.T) {
	ctx := context.Background()
	q := openStore(t).Read()
	admin, err := q.GetBuiltinRole(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.ListGrantsForRole(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []Permission
	for _, r := range rows {
		if r.ScopeType != string(ScopeAll) {
			t.Errorf("admin grant %s has scope %s, want all", r.Permission, r.ScopeType)
		}
		got = append(got, Permission(r.Permission))
	}
	var want []Permission
	for _, p := range Catalogue() {
		want = append(want, p.Name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("builtin admin grants =\n  %v\ncatalogue =\n  %v", got, want)
	}
}
