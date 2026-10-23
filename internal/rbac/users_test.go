// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
)

func TestCreateLocalUser(t *testing.T) {
	e := newEnv(t)
	root := e.actor(e.local("root", e.admin))
	staff := e.role("staff", g(ClientsEdit, AllScope()))
	hr := e.actor(e.local("hr", e.role("hr", g(UsersManage, AllScope()))))

	id, err := e.m.CreateLocalUser(e.ctx, root, " Grace ", "correct horse battery", []int64{staff, staff})
	wantCode(t, err, "")
	if got := e.userRoles(id); !slices.Equal(got, []int64{staff}) {
		t.Errorf("roles = %v", got)
	}
	u, _ := e.st.Read().GetUser(e.ctx, id)
	if u.Username != "grace" || u.PasswordHash.String == "correct horse battery" {
		t.Errorf("user = %+v", u)
	}

	_, err = e.m.CreateLocalUser(e.ctx, root, "grace", "correct horse battery", nil)
	wantCode(t, err, CodeConflict)
	_, err = e.m.CreateLocalUser(e.ctx, root, "-bad", "correct horse battery", nil)
	wantCode(t, err, CodeValidation)
	_, err = e.m.CreateLocalUser(e.ctx, root, "heidi", "short", nil)
	wantCode(t, err, CodeValidation)
	_, err = e.m.CreateLocalUser(e.ctx, root, "heidi", "correct horse battery", []int64{999})
	wantCode(t, err, CodeValidation)
	// users.manage alone can create users, but can't give them roles beyond the actor's own.
	_, err = e.m.CreateLocalUser(e.ctx, hr, "ivan", "correct horse battery", []int64{staff})
	wantCode(t, err, CodeForbidden)
	_, err = e.m.CreateLocalUser(e.ctx, hr, "ivan", "correct horse battery", nil)
	wantCode(t, err, "")
}

func TestSetUserRoles(t *testing.T) {
	e := newEnv(t)
	rootID := e.local("root", e.admin)
	root := e.actor(rootID)
	staff := e.role("staff", g(ClientsEdit, AllScope()))
	reader := e.role("reader", g(DomainsView, AllScope()))
	// A user manager who holds staff's and reader's grants, but not admin's.
	hr := e.actor(e.local("hr", e.role("hr", g(UsersManage, AllScope()), g(ClientsEdit, AllScope()), g(DomainsView, AllScope()))))
	judy := e.local("judy", staff)
	s1 := e.session(judy, t0, staff)
	e.session(judy, t0, staff)

	// The manager can move judy between roles they hold.
	wantCode(t, e.m.SetUserRoles(e.ctx, hr, judy, []int64{reader, staff}, false), "")
	if got := e.userRoles(judy); !slices.Equal(got, []int64{staff, reader}) && !slices.Equal(got, []int64{reader, staff}) {
		t.Errorf("roles = %v", got)
	}
	for _, s := range e.sessions(judy) {
		if got := e.sessionRoles(s); len(got) != 2 {
			t.Errorf("session %s roles = %v, want both", s.PublicID, got)
		}
	}

	// ... but can't make anyone an admin, or touch an admin's roles (invariant 7).
	wantCode(t, e.m.SetUserRoles(e.ctx, hr, judy, []int64{e.admin}, false), CodeForbidden)
	wantDenied(t, e, audit.ActionUserRoles)
	wantCode(t, e.m.SetUserRoles(e.ctx, hr, rootID, []int64{reader}, false), CodeForbidden)

	// Removing every role ends the sessions.
	wantCode(t, e.m.SetUserRoles(e.ctx, root, judy, nil, false), "")
	if n := len(e.sessions(judy)); n != 0 {
		t.Errorf("%d sessions left (first was %s), want 0", n, s1)
	}

	// LDAP users get their roles from mappings.
	wantCode(t, e.m.SetUserRoles(e.ctx, root, e.ldapUser("ken"), []int64{reader}, false), CodeValidation)
	wantCode(t, e.m.SetUserRoles(e.ctx, root, 999, nil, false), CodeNotFound)
}

func TestSetUserRolesKeepsAnAdmin(t *testing.T) {
	e := newEnv(t)
	rootID := e.local("root", e.admin)
	root := e.actor(rootID)
	reader := e.role("reader", g(DomainsView, AllScope()))

	// Invariant 2 holds even when the change is confirmed.
	wantCode(t, e.m.SetUserRoles(e.ctx, root, rootID, []int64{reader}, true), CodeInvariant)
	if got := e.userRoles(rootID); !slices.Equal(got, []int64{e.admin}) {
		t.Errorf("roles changed despite the refusal: %v", got)
	}

	// An LDAP admin doesn't count.
	lee := e.ldapUser("lee")
	e.session(lee, t0, e.admin)
	wantCode(t, e.m.SetUserRoles(e.ctx, root, rootID, []int64{reader}, true), CodeInvariant)

	// A disabled local admin doesn't count either.
	other := e.local("other", e.admin)
	wantCode(t, e.m.SetUserDisabled(e.ctx, root, other, true, false), "")
	wantCode(t, e.m.SetUserRoles(e.ctx, root, rootID, []int64{reader}, true), CodeInvariant)

	// With a second enabled local admin, it needs only the self-demotion confirmation (invariant 4).
	wantCode(t, e.m.SetUserDisabled(e.ctx, root, other, false, false), "")
	wantCode(t, e.m.SetUserRoles(e.ctx, root, rootID, []int64{reader}, false), CodeConfirmation)
	wantCode(t, e.m.SetUserRoles(e.ctx, root, rootID, []int64{reader}, true), "")
}

func TestSetUserDisabled(t *testing.T) {
	e := newEnv(t)
	rootID := e.local("root", e.admin)
	root := e.actor(rootID)
	staff := e.role("staff", g(ClientsEdit, AllScope()))
	hr := e.actor(e.local("hr", e.role("hr", g(UsersManage, AllScope()), g(ClientsEdit, AllScope()))))
	mia := e.local("mia", staff)
	e.session(mia, t0, staff)

	wantCode(t, e.m.SetUserDisabled(e.ctx, hr, rootID, true, true), CodeForbidden)
	wantCode(t, e.m.SetUserDisabled(e.ctx, root, rootID, true, false), CodeConfirmation)
	wantCode(t, e.m.SetUserDisabled(e.ctx, root, rootID, true, true), CodeInvariant)

	wantCode(t, e.m.SetUserDisabled(e.ctx, hr, mia, true, false), "")
	if len(e.sessions(mia)) != 0 {
		t.Error("disabling left sessions")
	}
	if row := e.lastAudit(); row.Action != audit.ActionUserDisable || detail(t, row)["sessions_ended"] != float64(1) {
		t.Errorf("audit = %s %s", row.Action, row.Detail)
	}
	before := e.auditCount()
	wantCode(t, e.m.SetUserDisabled(e.ctx, hr, mia, true, false), "")
	if e.auditCount() != before {
		t.Error("disabling a disabled user was audited")
	}
	wantCode(t, e.m.SetUserDisabled(e.ctx, hr, mia, false, false), "")
	if e.lastAudit().Action != audit.ActionUserEnable {
		t.Error("enable not audited")
	}

	// An LDAP user's roles are those their sessions hold, for invariant 7.
	nina := e.ldapUser("nina")
	e.session(nina, t0, e.admin)
	wantCode(t, e.m.SetUserDisabled(e.ctx, hr, nina, true, false), CodeForbidden)
	wantCode(t, e.m.SetUserDisabled(e.ctx, root, nina, true, false), "")
}

func TestDeleteUser(t *testing.T) {
	e := newEnv(t)
	rootID := e.local("root", e.admin)
	root := e.actor(rootID)
	hr := e.actor(e.local("hr", e.role("hr", g(UsersManage, AllScope()))))
	olga := e.local("olga")

	wantCode(t, e.m.DeleteUser(e.ctx, hr, rootID, true), CodeForbidden)
	wantCode(t, e.m.DeleteUser(e.ctx, root, rootID, true), CodeInvariant)
	wantCode(t, e.m.DeleteUser(e.ctx, hr, olga, false), "")
	wantCode(t, e.m.DeleteUser(e.ctx, hr, olga, false), CodeNotFound)

	// Deleting oneself, with another admin left, needs confirmation; the audit row keeps the username.
	e.local("backup", e.admin)
	wantCode(t, e.m.DeleteUser(e.ctx, root, rootID, false), CodeConfirmation)
	wantCode(t, e.m.DeleteUser(e.ctx, root, rootID, true), "")
	row := e.lastAudit()
	if row.Action != audit.ActionUserDelete || row.UserID.Valid || row.Username != "root" || row.Target != "user:root" {
		t.Errorf("audit row = %+v", row)
	}
}

func TestSetUserPassword(t *testing.T) {
	e := newEnv(t)
	rootID := e.local("root", e.admin)
	staff := e.role("staff", g(ClientsEdit, AllScope()))
	hr := e.actor(e.local("hr", e.role("hr", g(UsersManage, AllScope()), g(ClientsEdit, AllScope()))))
	pat := e.local("pat", staff)
	e.session(pat, t0, staff)

	// The case this invariant exists for: a user manager can't reset an admin's password and take the account over.
	wantCode(t, e.m.SetUserPassword(e.ctx, hr, rootID, "correct horse battery"), CodeForbidden)
	wantDenied(t, e, audit.ActionUserPassword)

	wantCode(t, e.m.SetUserPassword(e.ctx, hr, pat, "short"), CodeValidation)
	wantCode(t, e.m.SetUserPassword(e.ctx, hr, pat, "correct horse battery"), "")
	if len(e.sessions(pat)) != 0 {
		t.Error("password change left sessions")
	}
	wantCode(t, e.m.SetUserPassword(e.ctx, e.actor(rootID), e.ldapUser("quinn"), "correct horse battery"), CodeValidation)

	// Setting one's own password keeps the current session and ends the others.
	root := e.actor(rootID)
	root.PublicID = e.session(rootID, t0, e.admin)
	e.session(rootID, t0, e.admin)
	wantCode(t, e.m.SetUserPassword(e.ctx, root, rootID, "another long password"), "")
	if s := e.sessions(rootID); len(s) != 1 || s[0].PublicID != root.PublicID {
		t.Errorf("sessions after own password change = %v", s)
	}
}
