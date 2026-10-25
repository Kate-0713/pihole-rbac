-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Every stored (tier 2) secret, for rotate-key. Re-encrypting one changes only its ciphertext, nonce and key ID: the
-- secret itself, and who last set it when, stay as they were.

-- name: ListSealedInstancePasswords :many
SELECT id, name, password_ciphertext, password_nonce, password_key_id FROM instances
WHERE password_ciphertext IS NOT NULL ORDER BY id;

-- name: ListSealedSettings :many
SELECT key, secret_ciphertext, secret_nonce, secret_key_id FROM settings
WHERE secret_ciphertext IS NOT NULL ORDER BY key;

-- name: ListSealedChannelSecrets :many
SELECT id, name, secret_ciphertext, secret_nonce, secret_key_id FROM notification_channels
WHERE secret_ciphertext IS NOT NULL ORDER BY id;

-- name: ReencryptInstancePassword :exec
UPDATE instances SET password_ciphertext = ?, password_nonce = ?, password_key_id = ? WHERE id = ?;

-- name: ReencryptSettingSecret :exec
UPDATE settings SET secret_ciphertext = ?, secret_nonce = ?, secret_key_id = ? WHERE key = ?;

-- name: ReencryptChannelSecret :exec
UPDATE notification_channels SET secret_ciphertext = ?, secret_nonce = ?, secret_key_id = ? WHERE id = ?;
