// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package e2e prepares the servers the browser tests in web/e2e run against: a data directory seeded with users,
// roles and instances, written straight to the database before the real binary starts on it. The command that runs
// them is cmd/e2e-server. None of this is part of the app.
package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/auth/ldaptest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/setup"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// PiholePassword is the app password every fake Pi-hole accepts.
const PiholePassword = "e2e-pihole-password"

// User is a local account the tests log in as.
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	About    string `json:"about"`
}

// Instance is a Pi-hole instance in the seeded database. ID is set by Seed.
type Instance struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	EnvName string `json:"env_name"`
	BaseURL string `json:"base_url"`
}

// Target is the instance's API target, as in ?target=.
func (i Instance) Target() string { return fmt.Sprintf("i-%d", i.ID) }

// Fixture is what the seeded server starts with. The tests read it from the e2e server's /state, so names and
// passwords live in one place.
type Fixture struct {
	Admin User `json:"admin"`
	// OneInstance can view domains, clients and the query log on the first instance only.
	OneInstance User `json:"one_instance"`
	// NoInstances holds a global permission (audit.view) and nothing on any instance.
	NoInstances User `json:"no_instances"`
	// RoleLead holds roles.manage and domains.view on all instances through an editable role, e2e-role-lead, so tests
	// can take roles.manage away from someone and see the confirmation it needs.
	RoleLead User `json:"role_lead"`
	// UserLead holds users.manage and domains.view on all instances through an editable role, e2e-user-lead, so tests
	// can see what someone who manages users but isn't an admin may and may not do.
	UserLead  User       `json:"user_lead"`
	Instances []Instance `json:"instances"`
	// SpareEnvName has its password variable set on the seeded server but no instance, so a test can add an instance
	// that can be enabled: the fake Pi-holes all take the same password.
	SpareEnvName string `json:"spare_env_name"`
	// PiholePassword is the fake Pi-holes' app password, for tests that store or confirm one.
	PiholePassword string `json:"pihole_password"`
	// LDAP is the fake directory the e2e server starts, for the LDAP page's tests. Seed doesn't configure it: a test
	// that saves LDAP settings and turns LDAP login on turns it off again. Its users' passwords are their username
	// followed by "-ldap-password".
	LDAP *ldaptest.Fixture `json:"ldap,omitempty"`
	// Matrix is the fake homeserver the e2e server starts, for the notifications page's tests. What it received is on
	// the control address at GET /matrix?room=<room ID>.
	Matrix *MatrixFixture `json:"matrix,omitempty"`
}

// NewFixture returns the standard fixture for instances at the given base URLs, named pihole1, pihole2 and so on.
func NewFixture(baseURLs ...string) *Fixture {
	f := &Fixture{
		Admin:          User{Username: "admin", Password: "e2e-admin-password", About: "builtin admin role"},
		OneInstance:    User{Username: "alice", Password: "e2e-alice-password", About: "domains, clients and query log on pihole1"},
		NoInstances:    User{Username: "bob", Password: "e2e-bob-password", About: "audit.view only"},
		RoleLead:       User{Username: "carol", Password: "e2e-carol-password", About: "roles.manage and domains.view, through an editable role"},
		UserLead:       User{Username: "dave", Password: "e2e-dave-password", About: "users.manage and domains.view, through an editable role"},
		SpareEnvName:   "SPARE",
		PiholePassword: PiholePassword,
	}
	for i, u := range baseURLs {
		f.Instances = append(f.Instances, Instance{
			Name: fmt.Sprintf("pihole%d", i+1), EnvName: fmt.Sprintf("PIHOLE%d", i+1), BaseURL: u,
		})
	}
	return f
}

// Seed creates the database in dataDir and fills it from f in one transaction: the admin (which also closes
// first-run setup and creates the starter roles, as reset-admin does), the instances, enabled, and the limited
// users with their roles. It fills in the instances' IDs. The database must not exist yet.
func Seed(ctx context.Context, dataDir string, f *Fixture) error {
	if len(f.Instances) == 0 {
		return fmt.Errorf("e2e: the fixture needs at least one instance")
	}
	st, err := store.Open(ctx, store.Options{DataDir: dataDir, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return err
	}
	defer st.Close()

	now := time.Now()
	return st.WithTx(ctx, func(q *db.Queries) error {
		if _, err := setup.ResetAdmin(ctx, q, f.Admin.Username, f.Admin.Password, now); err != nil {
			return fmt.Errorf("admin: %w", err)
		}
		// Written directly, so enabling skips the connection test the API would run: the tests decide what each
		// instance's health turns out to be.
		for i := range f.Instances {
			inst := &f.Instances[i]
			id, err := q.CreateInstance(ctx, db.CreateInstanceParams{
				Name: inst.Name, BaseUrl: inst.BaseURL, EnvName: sql.NullString{String: inst.EnvName, Valid: true}, TlsMode: "verify", CreatedAt: store.Millis(now),
			})
			if err != nil {
				return fmt.Errorf("instance %s: %w", inst.Name, err)
			}
			if err := q.SetInstanceEnabled(ctx, db.SetInstanceEnabledParams{Enabled: true, ID: id}); err != nil {
				return err
			}
			inst.ID = id
		}

		first := sql.NullInt64{Int64: f.Instances[0].ID, Valid: true}
		oneRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "e2e-one-instance", Description: f.OneInstance.About, CreatedAt: store.Millis(now)})
		if err != nil {
			return err
		}
		for _, p := range []rbac.Permission{rbac.DomainsView, rbac.ClientsView, rbac.QueryLogView} {
			if err := q.InsertGrant(ctx, db.InsertGrantParams{RoleID: oneRole, Permission: string(p), ScopeType: "instance", InstanceID: first}); err != nil {
				return err
			}
		}
		noneRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "e2e-no-instances", Description: f.NoInstances.About, CreatedAt: store.Millis(now)})
		if err != nil {
			return err
		}
		if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: noneRole, Permission: string(rbac.AuditView)}); err != nil {
			return err
		}

		leadRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "e2e-role-lead", Description: f.RoleLead.About, CreatedAt: store.Millis(now)})
		if err != nil {
			return err
		}
		for _, p := range []rbac.Permission{rbac.RolesManage, rbac.DomainsView} {
			if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: leadRole, Permission: string(p)}); err != nil {
				return err
			}
		}

		userLeadRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "e2e-user-lead", Description: f.UserLead.About, CreatedAt: store.Millis(now)})
		if err != nil {
			return err
		}
		for _, p := range []rbac.Permission{rbac.UsersManage, rbac.DomainsView} {
			if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: userLeadRole, Permission: string(p)}); err != nil {
				return err
			}
		}

		for _, u := range []struct {
			user User
			role int64
		}{{f.OneInstance, oneRole}, {f.NoInstances, noneRole}, {f.RoleLead, leadRole}, {f.UserLead, userLeadRole}} {
			hash, err := auth.HashPassword(u.user.Password)
			if err != nil {
				return err
			}
			row, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{
				Username: u.user.Username, PasswordHash: sql.NullString{String: string(hash), Valid: true}, CreatedAt: store.Millis(now),
			})
			if err != nil {
				return fmt.Errorf("user %s: %w", u.user.Username, err)
			}
			if err := q.AddUserRole(ctx, db.AddUserRoleParams{UserID: row.ID, RoleID: u.role}); err != nil {
				return err
			}
		}
		return nil
	})
}
