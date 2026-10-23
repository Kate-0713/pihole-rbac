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

-- name: CreateInstance :one
INSERT INTO instances (name, base_url, env_name, created_at) VALUES (?, ?, ?, ?)
RETURNING id;

-- name: CreateInstanceGroup :one
INSERT INTO instance_groups (name, mode, primary_instance_id, created_at) VALUES (?, ?, ?, ?)
RETURNING id;

-- group_mode is copied from the group, which the composite foreign key requires.
-- name: AddInstanceGroupMember :exec
INSERT INTO instance_group_members (group_id, group_mode, instance_id)
SELECT g.id, g.mode, sqlc.arg(instance_id) FROM instance_groups g WHERE g.id = sqlc.arg(group_id);

-- name: ListInstanceEnvNames :many
SELECT env_name FROM instances ORDER BY env_name;
