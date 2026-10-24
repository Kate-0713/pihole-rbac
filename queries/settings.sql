-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: GetSetting :one
SELECT * FROM settings WHERE key = ?;

-- name: UpsertSetting :exec
INSERT INTO settings (key, value, updated_at, updated_by)
VALUES (?, ?, ?, ?)
ON CONFLICT (key) DO UPDATE SET
    value      = excluded.value,
    updated_at = excluded.updated_at,
    updated_by = excluded.updated_by;

-- The row must exist: save the setting first.
-- name: SetSettingSecret :execrows
UPDATE settings
SET secret_ciphertext = ?, secret_nonce = ?, secret_key_id = ?, secret_updated_at = ?, secret_updated_by = ?
WHERE key = ?;
