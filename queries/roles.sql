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

-- name: GetBuiltinRole :one
SELECT * FROM roles WHERE builtin = 1;

-- name: CreateRole :one
INSERT INTO roles (name, description, created_at) VALUES (?, ?, ?)
RETURNING id;

-- name: AddRoleGrantAll :exec
INSERT INTO role_grants (role_id, permission, scope_type) VALUES (?, ?, 'all');

-- name: ListGrantsForRoles :many
SELECT * FROM role_grants
WHERE role_id IN (sqlc.slice('role_ids'))
ORDER BY role_id, permission, scope_type, instance_id, group_id;

-- name: InsertGrant :exec
INSERT INTO role_grants (role_id, permission, scope_type, instance_id, group_id) VALUES (?, ?, ?, ?, ?);

-- name: GetRole :one
SELECT * FROM roles WHERE id = ?;

-- name: UpdateRole :exec
UPDATE roles SET name = ?, description = ? WHERE id = ?;

-- name: DeleteRole :exec
DELETE FROM roles WHERE id = ?;

-- name: DeleteRoleGrants :exec
DELETE FROM role_grants WHERE role_id = ?;

-- name: ListUsernamesWithRole :many
SELECT u.username FROM user_roles ur JOIN users u ON u.id = ur.user_id
WHERE ur.role_id = ?
ORDER BY u.username;

-- name: ListLDAPMappingsForRole :many
SELECT * FROM role_ldap_groups WHERE role_id = ? ORDER BY group_dn;

-- name: GetLDAPMapping :one
SELECT * FROM role_ldap_groups WHERE id = ?;

-- name: CreateLDAPMapping :one
INSERT INTO role_ldap_groups (role_id, group_dn, group_dn_norm, created_at) VALUES (?, ?, ?, ?)
RETURNING id;

-- name: DeleteLDAPMapping :exec
DELETE FROM role_ldap_groups WHERE id = ?;

-- Roles holding any of the given permissions on a group, for the mirrored-to-independent check.
-- name: ListRolesWithGrantsOnGroup :many
SELECT DISTINCT r.name FROM role_grants g JOIN roles r ON r.id = g.role_id
WHERE g.group_id = sqlc.arg(group_id) AND g.permission IN (sqlc.slice('permissions'))
ORDER BY r.name;
