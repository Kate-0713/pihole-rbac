-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = ?;

-- name: ListGrantsForRole :many
SELECT * FROM role_grants
WHERE role_id = ?
ORDER BY permission, scope_type, instance_id, group_id;

-- name: ListRoleIDsForLDAPGroups :many
SELECT DISTINCT role_id FROM role_ldap_groups
WHERE group_dn_norm IN (sqlc.slice('group_dns'))
ORDER BY role_id;

-- name: AddRoleLDAPGroup :exec
INSERT INTO role_ldap_groups (role_id, group_dn, group_dn_norm, created_at) VALUES (?, ?, ?, ?);
