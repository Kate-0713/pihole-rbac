// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package setup

import (
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// The starter roles are created with every grant at scope all, so each permission must be in the catalogue (which
// every class allows at scope all).
func TestStarterRolesUseCatalogue(t *testing.T) {
	for _, r := range StarterRoles {
		if len(r.Permissions) == 0 {
			t.Errorf("starter role %s has no permissions", r.Name)
		}
		for _, p := range r.Permissions {
			if err := rbac.ValidateGrant(rbac.NewTopology(nil, nil, nil), rbac.Grant{Permission: rbac.Permission(p), Scope: rbac.AllScope()}); err != nil {
				t.Errorf("starter role %s: %v", r.Name, err)
			}
		}
	}
}
