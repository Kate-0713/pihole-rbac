-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: ListChannels :many
SELECT * FROM notification_channels ORDER BY name COLLATE NOCASE, id;

-- name: GetChannel :one
SELECT * FROM notification_channels WHERE id = ?;

-- name: CreateChannel :one
INSERT INTO notification_channels (kind, name, env_name, config, enabled, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateChannel :exec
UPDATE notification_channels SET name = ?, env_name = ?, config = ?, enabled = ? WHERE id = ?;

-- name: SetChannelSecret :exec
UPDATE notification_channels
SET secret_ciphertext = ?, secret_nonce = ?, secret_key_id = ?, secret_updated_at = ?, secret_updated_by = ?
WHERE id = ?;

-- name: DeleteChannel :exec
DELETE FROM notification_channels WHERE id = ?;

-- name: ChannelNameTaken :one
-- Whether another channel has this name, ignoring case.
SELECT EXISTS (SELECT 1 FROM notification_channels WHERE name = ? COLLATE NOCASE AND id <> ?);

-- name: ChannelEnvNameTaken :one
SELECT EXISTS (SELECT 1 FROM notification_channels WHERE env_name = ? AND id <> ?);

-- name: ListChannelRules :many
SELECT event FROM notification_rules WHERE channel_id = ? ORDER BY event;

-- name: ListAllChannelRules :many
SELECT channel_id, event FROM notification_rules ORDER BY channel_id, event;

-- name: DeleteChannelRules :exec
DELETE FROM notification_rules WHERE channel_id = ?;

-- name: AddChannelRule :exec
INSERT INTO notification_rules (channel_id, event) VALUES (?, ?);

-- name: ListProtectedGroups :many
SELECT p.id, p.instance_id, p.group_id, p.pihole_group,
       COALESCE(i.name, '') AS instance_name, COALESCE(g.name, '') AS group_name, COALESCE(g.mode, '') AS group_mode
FROM notification_protected_groups p
LEFT JOIN instances i ON i.id = p.instance_id
LEFT JOIN instance_groups g ON g.id = p.group_id
ORDER BY p.group_id IS NOT NULL, COALESCE(i.name, g.name) COLLATE NOCASE, p.pihole_group COLLATE NOCASE;

-- name: DeleteAllProtectedGroups :exec
DELETE FROM notification_protected_groups;

-- name: AddProtectedGroup :exec
INSERT INTO notification_protected_groups (instance_id, group_id, pihole_group) VALUES (?, ?, ?);

-- name: ProtectedGroupsForInstance :many
-- The protected names that apply to an instance: its own, and those of the mirrored group it belongs to (an instance
-- is in at most one). An independent group's names never apply: it isn't a target.
SELECT DISTINCT p.pihole_group FROM notification_protected_groups p
WHERE p.instance_id = sqlc.arg(instance_id)
   OR p.group_id = (SELECT m.group_id FROM instance_group_members m
                    WHERE m.instance_id = sqlc.arg(instance_id) AND m.group_mode = 'mirrored');
