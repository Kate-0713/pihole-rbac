-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: ListInstanceIDs :many
SELECT id FROM instances ORDER BY id;

-- Every group with its members. A group without members appears once, with a NULL instance_id.
-- name: ListGroupMembership :many
SELECT g.id AS group_id, g.mode, m.instance_id
FROM instance_groups g
LEFT JOIN instance_group_members m ON m.group_id = g.id
ORDER BY g.id, m.instance_id;

-- name: ListInstances :many
SELECT * FROM instances ORDER BY name;

-- name: GetInstance :one
SELECT * FROM instances WHERE id = ?;

-- New instances start disabled; enabling one is a separate change that needs a successful connection test.
-- name: CreateInstance :one
INSERT INTO instances (name, base_url, env_name, tls_mode, ca_file, created_at) VALUES (?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateInstance :exec
UPDATE instances SET name = ?, base_url = ?, env_name = ?, tls_mode = ?, ca_file = ? WHERE id = ?;

-- name: SetInstancePassword :exec
UPDATE instances
SET password_ciphertext = ?, password_nonce = ?, password_key_id = ?, password_updated_at = ?, password_updated_by = ?
WHERE id = ?;

-- name: SetInstanceEnabled :exec
UPDATE instances SET enabled = ? WHERE id = ?;

-- name: DeleteInstance :exec
DELETE FROM instances WHERE id = ?;

-- What still refers to an instance, so a refused delete can say where it is used.
-- name: ListRolesWithGrantsOnInstance :many
SELECT DISTINCT r.name FROM role_grants g JOIN roles r ON r.id = g.role_id
WHERE g.instance_id = ?
ORDER BY r.name;

-- name: ListGroupsWithInstance :many
SELECT g.name FROM instance_group_members m JOIN instance_groups g ON g.id = m.group_id
WHERE m.instance_id = ?
ORDER BY g.name;

-- name: CountClientResetTargetsForInstance :one
SELECT COUNT(*) FROM client_reset_targets WHERE instance_id = ?;

-- name: CreateInstanceGroup :one
INSERT INTO instance_groups (name, mode, primary_instance_id, created_at) VALUES (?, ?, ?, ?)
RETURNING id;

-- group_mode is copied from the group, which the composite foreign key requires.
-- name: AddInstanceGroupMember :exec
INSERT INTO instance_group_members (group_id, group_mode, instance_id)
SELECT g.id, g.mode, sqlc.arg(instance_id) FROM instance_groups g WHERE g.id = sqlc.arg(group_id);

-- name: ListInstanceEnvNames :many
SELECT env_name FROM instances WHERE env_name IS NOT NULL ORDER BY env_name;

-- name: ListInstanceGroups :many
SELECT * FROM instance_groups ORDER BY name COLLATE NOCASE, id;

-- name: GetInstanceGroup :one
SELECT * FROM instance_groups WHERE id = ?;

-- name: ListInstanceGroupMembers :many
SELECT instance_id FROM instance_group_members WHERE group_id = ? ORDER BY instance_id;

-- The mode and primary change together, as the table's CHECK requires; a new mode reaches the members' group_mode
-- through the composite foreign key's ON UPDATE CASCADE.
-- name: UpdateInstanceGroup :exec
UPDATE instance_groups SET name = ?, mode = ?, primary_instance_id = ? WHERE id = ?;

-- name: RemoveInstanceGroupMember :exec
DELETE FROM instance_group_members WHERE group_id = ? AND instance_id = ?;

-- name: DeleteInstanceGroup :exec
DELETE FROM instance_groups WHERE id = ?;

-- What still refers to a group, so a refused delete can say where it is used.
-- name: ListRolesWithAnyGrantOnGroup :many
SELECT DISTINCT r.name FROM role_grants g JOIN roles r ON r.id = g.role_id
WHERE g.group_id = ?
ORDER BY r.name;

-- name: CountClientResetTargetsForGroup :one
SELECT COUNT(*) FROM client_reset_targets WHERE group_id = ?;

-- The mirrored group an instance belongs to, if any; there is at most one.
-- name: GetMirroredGroupOfInstance :one
SELECT g.id, g.name FROM instance_group_members m JOIN instance_groups g ON g.id = m.group_id
WHERE m.instance_id = ? AND m.group_mode = 'mirrored';
