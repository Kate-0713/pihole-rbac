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
