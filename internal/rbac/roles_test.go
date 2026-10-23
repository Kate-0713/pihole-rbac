// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"slices"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

func TestCreateRole(t *testing.T) {
	e := newEnv(t)
	root := e.local("root", e.admin)
	// A delegated role manager: roles.manage, plus domains.view on the independent group only.
	delegate := e.local("delegate", e.role("delegated",
		g(RolesManage, AllScope()), g(DomainsView, GroupScope(e.indep))))
	nobody := e.local("nobody", e.role("viewer", g(DomainsView, AllScope())))

	tests := []struct {
		name   string
		actor  int64
		in     RoleInput
		grants []Grant
		code   Code
	}{
		{"admin creates a role", root, RoleInput{Name: " helpdesk ", Description: "Front line"},
			[]Grant{g(ClientsEdit, GroupScope(e.mirror)), g(DomainsView, AllScope()), g(DomainsView, AllScope())}, ""},
		{"no roles.manage", nobody, RoleInput{Name: "x"}, nil, CodeForbidden},
		{"delegate grants within their group", delegate, RoleInput{Name: "site-viewer"}, []Grant{g(DomainsView, GroupScope(e.indep))}, ""},
		{"delegate grants on a member of their group", delegate, RoleInput{Name: "one-viewer"}, []Grant{g(DomainsView, InstanceScope(e.inst1))}, ""},
		{"delegate can't grant wider", delegate, RoleInput{Name: "wide"}, []Grant{g(DomainsView, AllScope())}, CodeForbidden},
		{"delegate can't grant outside their group", delegate, RoleInput{Name: "three"}, []Grant{g(DomainsView, InstanceScope(e.inst3))}, CodeForbidden},
		{"delegate can't grant what they lack", delegate, RoleInput{Name: "users"}, []Grant{g(UsersManage, AllScope())}, CodeForbidden},
		{"invalid scope", root, RoleInput{Name: "bad"}, []Grant{g(DriftView, GroupScope(e.indep))}, CodeInvariant},
		{"unknown permission", root, RoleInput{Name: "bad"}, []Grant{g("domains.delete", AllScope())}, CodeValidation},
		{"empty name", root, RoleInput{Name: "  "}, nil, CodeValidation},
		{"control character", root, RoleInput{Name: "a\x00b"}, nil, CodeValidation},
		{"name taken, any case", root, RoleInput{Name: "ADMIN"}, nil, CodeConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := e.auditCount()
			id, err := e.m.CreateRole(e.ctx, e.actor(tt.actor), tt.in, tt.grants)
			wantCode(t, err, tt.code)
			switch tt.code {
			case "":
				if id == 0 {
					t.Fatal("no role ID")
				}
				row := e.lastAudit()
				if row.Action != audit.ActionRoleCreate || row.Result != audit.ResultSuccess {
					t.Errorf("audit = %s %s", row.Action, row.Result)
				}
			case CodeForbidden:
				wantDenied(t, e, audit.ActionRoleCreate)
			default:
				if e.auditCount() != before {
					t.Error("a refused change that isn't about permissions was audited")
				}
			}
		})
	}

	// The first case stored its grants without the duplicate, and trimmed the name.
	r, err := e.st.Read().GetRoleByName(e.ctx, "helpdesk")
	if err != nil {
		t.Fatal(err)
	}
	want := []Grant{g(ClientsEdit, GroupScope(e.mirror)), g(DomainsView, AllScope())}
	if got := e.grants(r.ID); !slices.Equal(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
}

func TestBuiltinAdminCantBeChanged(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	wantCode(t, e.m.UpdateRole(e.ctx, root, e.admin, RoleInput{Name: "boss"}), CodeInvariant)
	wantCode(t, e.m.SetRoleGrants(e.ctx, root, e.admin, []Grant{g(DomainsView, AllScope())}, true), CodeInvariant)
	wantCode(t, e.m.DeleteRole(e.ctx, root, e.admin), CodeInvariant)
	if got := len(e.grants(e.admin)); got != len(Catalogue()) {
		t.Errorf("admin has %d grants after refused changes, want %d", got, len(Catalogue()))
	}
}

func TestUpdateRole(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	staff := e.role("staff", g(ClientsEdit, AllScope()))
	e.role("reader")
	// Holds roles.manage but not clients.edit, so can't touch staff.
	limited := e.actor(e.local("limited", e.role("limited", g(RolesManage, AllScope()))))

	wantCode(t, e.m.UpdateRole(e.ctx, limited, staff, RoleInput{Name: "staff2"}), CodeForbidden)
	wantCode(t, e.m.UpdateRole(e.ctx, root, staff, RoleInput{Name: "Reader"}), CodeConflict)
	wantCode(t, e.m.UpdateRole(e.ctx, root, 999, RoleInput{Name: "x"}), CodeNotFound)

	before := e.auditCount()
	wantCode(t, e.m.UpdateRole(e.ctx, root, staff, RoleInput{Name: "staff"}), "")
	if e.auditCount() != before {
		t.Error("an update that changed nothing was audited")
	}
	wantCode(t, e.m.UpdateRole(e.ctx, root, staff, RoleInput{Name: "operators", Description: "Ops"}), "")
	if d := detail(t, e.lastAudit()); d["renamed_from"] != "staff" {
		t.Errorf("audit detail = %v", d)
	}
}

func TestSetRoleGrants(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	staff := e.role("staff", g(ClientsEdit, AllScope()), g(DomainsView, AllScope()))
	// roles.manage and domains.view everywhere, but not clients.edit.
	limited := e.actor(e.local("limited", e.role("limited", g(RolesManage, AllScope()), g(DomainsView, AllScope()))))

	// Removing a grant the actor doesn't hold is refused: invariant 3 covers the role before the change too.
	wantCode(t, e.m.SetRoleGrants(e.ctx, limited, staff, []Grant{g(DomainsView, AllScope())}, false), CodeForbidden)
	wantDenied(t, e, audit.ActionRoleGrants)

	wantCode(t, e.m.SetRoleGrants(e.ctx, root, staff, []Grant{g(DriftReconcile, GroupScope(e.indep))}, false), CodeInvariant)

	wantCode(t, e.m.SetRoleGrants(e.ctx, root, staff, []Grant{
		g(DomainsView, AllScope()), g(ClientsView, InstanceScope(e.inst1)), g(DriftView, GroupScope(e.mirror)),
	}, false), "")
	want := []Grant{g(ClientsView, InstanceScope(e.inst1)), g(DomainsView, AllScope()), g(DriftView, GroupScope(e.mirror))}
	if got := e.grants(staff); !slices.Equal(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
	d := detail(t, e.lastAudit())
	if len(d["added"].([]any)) != 2 || len(d["removed"].([]any)) != 1 {
		t.Errorf("audit detail = %v", d)
	}

	before := e.auditCount()
	wantCode(t, e.m.SetRoleGrants(e.ctx, root, staff, want, false), "")
	if e.auditCount() != before {
		t.Error("setting the same grants was audited")
	}
}

func TestSetRoleGrantsSelfDemotion(t *testing.T) {
	e := newEnv(t)
	e.local("root", e.admin)
	managers := e.role("managers", g(RolesManage, AllScope()), g(UsersManage, AllScope()))
	viewers := e.role("viewers", g(DomainsView, AllScope()))
	alice := e.actor(e.local("alice", managers, viewers))

	// Taking roles.manage out of alice's only route to it needs confirmation.
	err := e.m.SetRoleGrants(e.ctx, alice, managers, []Grant{g(UsersManage, AllScope())}, false)
	wantCode(t, err, CodeConfirmation)
	if ee, _ := AsError(err); !slices.Equal(ee.Details["would_lose"].([]Permission), []Permission{RolesManage}) {
		t.Errorf("details = %v", ee.Details)
	}
	// Changing a role alice doesn't hold never asks.
	wantCode(t, e.m.SetRoleGrants(e.ctx, alice, viewers, nil, false), "")
	// Confirmed, it goes ahead.
	wantCode(t, e.m.SetRoleGrants(e.ctx, alice, managers, []Grant{g(UsersManage, AllScope())}, true), "")

	// With a second route to roles.manage, no confirmation is needed.
	e2 := newEnv(t)
	e2.local("root", e2.admin)
	m1 := e2.role("m1", g(RolesManage, AllScope()))
	m2 := e2.role("m2", g(RolesManage, AllScope()))
	bob := e2.actor(e2.local("bob", m1, m2))
	wantCode(t, e2.m.SetRoleGrants(e2.ctx, bob, m1, nil, false), "")
}

func TestDeleteRole(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	used := e.role("used", g(DomainsView, AllScope()))
	mapped := e.role("mapped", g(DomainsView, AllScope()))
	unused := e.role("unused", g(DomainsView, AllScope()))
	e.local("carol", used)
	if _, err := e.m.AddLDAPMapping(e.ctx, root, mapped, "cn=Staff,dc=example"); err != nil {
		t.Fatal(err)
	}

	err := e.m.DeleteRole(e.ctx, root, used)
	wantCode(t, err, CodeInvariant)
	if ee, _ := AsError(err); !slices.Equal(ee.Details["users"].([]string), []string{"carol"}) {
		t.Errorf("details = %v", ee.Details)
	}
	err = e.m.DeleteRole(e.ctx, root, mapped)
	wantCode(t, err, CodeInvariant)
	if ee, _ := AsError(err); !slices.Equal(ee.Details["ldap_groups"].([]string), []string{"cn=Staff,dc=example"}) {
		t.Errorf("details = %v", ee.Details)
	}

	limited := e.actor(e.local("limited", e.role("limited", g(RolesManage, AllScope()))))
	wantCode(t, e.m.DeleteRole(e.ctx, limited, unused), CodeForbidden)

	wantCode(t, e.m.DeleteRole(e.ctx, root, unused), "")
	if _, _, err := (&txn{ctx: e.ctx, q: e.st.Read()}).role(unused); !IsCode(err, CodeNotFound) {
		t.Errorf("role still there: %v", err)
	}
	if len(e.grants(unused)) != 0 {
		t.Error("grants of a deleted role remain")
	}
}

func TestLDAPMappings(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	staff := e.role("staff", g(DomainsView, AllScope()))
	limited := e.actor(e.local("limited", e.role("limited", g(RolesManage, AllScope()), g(DomainsView, AllScope()))))

	id, err := e.m.AddLDAPMapping(e.ctx, root, staff, "  CN=Pi-hole Staff, OU=Groups,DC=Example,DC=com ")
	wantCode(t, err, "")
	mp, err := e.st.Read().GetLDAPMapping(e.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if mp.GroupDn != "CN=Pi-hole Staff, OU=Groups,DC=Example,DC=com" || mp.GroupDnNorm != "cn=pi-hole staff,ou=groups,dc=example,dc=com" {
		t.Errorf("mapping = %q / %q", mp.GroupDn, mp.GroupDnNorm)
	}

	_, err = e.m.AddLDAPMapping(e.ctx, root, staff, "cn=pi-hole staff,ou=groups,dc=example,dc=com")
	wantCode(t, err, CodeConflict)
	for _, bad := range []string{"", "   ", "not a dn", "cn=a\nb,dc=example"} {
		_, err = e.m.AddLDAPMapping(e.ctx, root, staff, bad)
		wantCode(t, err, CodeValidation)
	}
	// Only someone holding every admin grant can map the admin role.
	_, err = e.m.AddLDAPMapping(e.ctx, limited, e.admin, "cn=admins,dc=example")
	wantCode(t, err, CodeForbidden)
	wantDenied(t, e, audit.ActionLDAPMappingAdd)
	_, err = e.m.AddLDAPMapping(e.ctx, limited, staff, "cn=helpdesk,dc=example")
	wantCode(t, err, "")

	// Removing a mapping makes LDAP sessions holding the role due for recheck, and leaves local sessions alone.
	dave := e.ldapUser("dave")
	recent := e.session(dave, t0.Add(-time.Minute), staff)
	stale := e.session(dave, t0.Add(-25*time.Minute), staff)
	erin := e.local("erin", staff)
	e.session(erin, t0.Add(-time.Minute), staff)
	other := e.ldapUser("other")
	e.session(other, t0.Add(-time.Minute))

	wantCode(t, e.m.RemoveLDAPMapping(e.ctx, root, id, false), "")
	due := store.Millis(t0.Add(-auth.DefaultRecheckInterval))
	for _, s := range e.sessions(dave) {
		switch s.PublicID {
		case recent:
			if s.RolesCheckedAt != due {
				t.Errorf("recent LDAP session checked at %d, want %d", s.RolesCheckedAt, due)
			}
		case stale:
			if s.RolesCheckedAt != store.Millis(t0.Add(-25*time.Minute)) {
				t.Error("an already-due session was moved later, extending its grace period")
			}
		}
	}
	if s := e.sessions(erin)[0]; s.RolesCheckedAt != store.Millis(t0.Add(-time.Minute)) {
		t.Error("a local session was marked for recheck")
	}
	if s := e.sessions(other)[0]; s.RolesCheckedAt != store.Millis(t0.Add(-time.Minute)) {
		t.Error("an LDAP session without the role was marked for recheck")
	}
	if d := detail(t, e.lastAudit()); d["sessions_rechecked"] != float64(2) {
		t.Errorf("audit detail = %v", d)
	}
	wantCode(t, e.m.RemoveLDAPMapping(e.ctx, root, id, false), CodeNotFound)
}

func TestRemoveLDAPMappingSelfDemotion(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	managers := e.role("managers", g(RolesManage, AllScope()))
	id, err := e.m.AddLDAPMapping(e.ctx, root, managers, "cn=managers,dc=example")
	if err != nil {
		t.Fatal(err)
	}
	frank := e.ldapUser("frank")
	e.session(frank, t0, managers)
	a := e.actor(frank)

	wantCode(t, e.m.RemoveLDAPMapping(e.ctx, a, id, false), CodeConfirmation)
	wantCode(t, e.m.RemoveLDAPMapping(e.ctx, a, id, true), "")
}

func TestCheckGroupModeChange(t *testing.T) {
	e := newEnv(t)
	e.role("drifters", g(DriftView, GroupScope(e.mirror)), g(DomainsView, GroupScope(e.mirror)))
	e.role("editors", g(DomainsEdit, GroupScope(e.mirror)))
	q := e.st.Read()

	err := CheckGroupModeChange(e.ctx, q, e.mirror, Independent)
	wantCode(t, err, CodeInvariant)
	if ee, _ := AsError(err); !slices.Equal(ee.Details["roles"].([]string), []string{"drifters"}) {
		t.Errorf("details = %v", ee.Details)
	}
	wantCode(t, CheckGroupModeChange(e.ctx, q, e.mirror, Mirrored), "")
	wantCode(t, CheckGroupModeChange(e.ctx, q, e.indep, Independent), "")
}
