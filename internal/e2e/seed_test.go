// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package e2e

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// TestSeed: the seeded database is what the browser tests expect. Setup is closed, every user can log in, and each
// holds exactly the permissions the fixture describes.
func TestSeed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	f := NewFixture("http://127.0.0.1:1", "http://127.0.0.1:2")
	if err := Seed(ctx, dir, f); err != nil {
		t.Fatal(err)
	}
	if f.Instances[0].ID == 0 || f.Instances[1].ID == 0 || f.Instances[0].Target() == f.Instances[1].Target() {
		t.Fatalf("instances %+v", f.Instances)
	}

	st, err := store.Open(ctx, store.Options{DataDir: dir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if open, err := setup.Required(ctx, st.Read()); err != nil || open {
		t.Fatalf("setup still open: %v %v", open, err)
	}
	insts, err := st.Read().ListInstances(ctx)
	if err != nil || len(insts) != 2 || !insts[0].Enabled || !insts[1].Enabled {
		t.Fatalf("instances %+v %v", insts, err)
	}

	login := auth.NewLocalAuthenticator(auth.StoreUsers{St: st})
	perms := func(u User) *rbac.Set {
		t.Helper()
		id, err := login.Authenticate(ctx, u.Username, u.Password)
		if err != nil {
			t.Fatalf("%s can't log in: %v", u.Username, err)
		}
		roles, err := st.Read().ListUserRoleIDs(ctx, id.UserID)
		if err != nil {
			t.Fatal(err)
		}
		set, err := rbac.Resolve(ctx, st.Read(), roles)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	first, second := rbac.InstanceTarget(f.Instances[0].ID), rbac.InstanceTarget(f.Instances[1].ID)

	admin := perms(f.Admin)
	if !admin.CanGlobal(rbac.UsersManage) || !admin.Can(rbac.DomainsEdit, second) {
		t.Error("admin isn't an admin")
	}

	alice := perms(f.OneInstance)
	if !alice.Can(rbac.DomainsView, first) || !alice.Can(rbac.ClientsView, first) || !alice.Can(rbac.QueryLogView, first) {
		t.Error("one-instance user can't view the first instance")
	}
	if alice.Can(rbac.DomainsEdit, first) || alice.CanAny(second) || len(alice.Global()) != 0 {
		t.Error("one-instance user holds more than the fixture says")
	}

	bob := perms(f.NoInstances)
	if !bob.CanGlobal(rbac.AuditView) || bob.CanAny(first) || bob.CanAny(second) || len(bob.Global()) != 1 {
		t.Error("no-instances user holds more than audit.view")
	}

	carol := perms(f.RoleLead)
	if !carol.CanGlobal(rbac.RolesManage) || !carol.Can(rbac.DomainsView, second) || carol.CanGlobal(rbac.UsersManage) || len(carol.Global()) != 1 {
		t.Error("role lead doesn't hold exactly roles.manage and domains.view")
	}
}
