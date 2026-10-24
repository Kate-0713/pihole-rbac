// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import "testing"

func TestForbiddenEither(t *testing.T) {
	tests := []struct {
		perms []Permission
		msg   string
		names string
	}{
		{[]Permission{RolesManage}, "You need the roles.manage permission to do that.", "roles.manage"},
		{[]Permission{RolesManage, UsersManage}, "You need the roles.manage or users.manage permission to do that.", "roles.manage|users.manage"},
		{[]Permission{RolesManage, UsersManage, AuditView}, "You need the roles.manage, users.manage or audit.view permission to do that.", "roles.manage|users.manage|audit.view"},
	}
	for _, tt := range tests {
		e := ForbiddenEither(tt.perms...)
		if e.Code != CodeForbidden || e.Message != tt.msg || e.Details["permission"] != tt.names {
			t.Errorf("ForbiddenEither(%v) = %+v", tt.perms, e)
		}
	}
}
