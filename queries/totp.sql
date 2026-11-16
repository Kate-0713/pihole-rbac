-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: GetUserTOTP :one
SELECT * FROM user_totp WHERE user_id = ?;

-- Starts or restarts enrolment: a new secret that isn't enabled yet. It only replaces a secret that isn't enabled,
-- so the caller can tell from the row count that an enabled one was left alone.
-- name: SetPendingUserTOTP :execrows
INSERT INTO user_totp (user_id, secret_ciphertext, secret_nonce, secret_key_id, created_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET
    secret_ciphertext = excluded.secret_ciphertext,
    secret_nonce      = excluded.secret_nonce,
    secret_key_id     = excluded.secret_key_id,
    created_at        = excluded.created_at,
    last_step         = 0
WHERE user_totp.enabled_at IS NULL;

-- name: EnableUserTOTP :execrows
UPDATE user_totp SET enabled_at = sqlc.arg(enabled_at), last_step = sqlc.arg(last_step)
WHERE user_id = sqlc.arg(user_id) AND enabled_at IS NULL;

-- Records the time step of an accepted code. No row changes if that step, or a later one, was already used, which is
-- how a replayed code is refused even when two requests race.
-- name: AdvanceUserTOTPStep :execrows
UPDATE user_totp SET last_step = sqlc.arg(step)
WHERE user_id = sqlc.arg(user_id) AND enabled_at IS NOT NULL AND last_step < sqlc.arg(step);

-- Removes a user's TOTP, pending or enabled. Their recovery codes go with it.
-- name: DeleteUserTOTP :execrows
DELETE FROM user_totp WHERE user_id = ?;

-- name: AddRecoveryCode :exec
INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?);

-- name: DeleteRecoveryCodes :exec
DELETE FROM user_recovery_codes WHERE user_id = ?;

-- Spends a recovery code. No row changes if the user has no such code or it was used before.
-- name: UseRecoveryCode :execrows
UPDATE user_recovery_codes SET used_at = sqlc.arg(used_at)
WHERE user_id = sqlc.arg(user_id) AND code_hash = sqlc.arg(code_hash) AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL;

-- The users with TOTP on, for the users list.
-- name: ListTOTPUserIDs :many
SELECT user_id FROM user_totp WHERE enabled_at IS NOT NULL ORDER BY user_id;

-- name: SetRoleTOTPRequired :exec
INSERT INTO role_totp_required (role_id, set_at, set_by) VALUES (?, ?, ?)
ON CONFLICT (role_id) DO NOTHING;

-- name: ClearRoleTOTPRequired :execrows
DELETE FROM role_totp_required WHERE role_id = ?;

-- name: ListTOTPRequiredRoleIDs :many
SELECT role_id FROM role_totp_required ORDER BY role_id;

-- name: GetUserTOTPPolicy :one
SELECT * FROM user_totp_policy WHERE user_id = ?;

-- name: SetUserTOTPPolicy :exec
INSERT INTO user_totp_policy (user_id, policy, set_at, set_by) VALUES (?, ?, ?, ?)
ON CONFLICT (user_id) DO UPDATE SET policy = excluded.policy, set_at = excluded.set_at, set_by = excluded.set_by;

-- name: ClearUserTOTPPolicy :execrows
DELETE FROM user_totp_policy WHERE user_id = ?;

-- name: ListUserTOTPPolicies :many
SELECT * FROM user_totp_policy ORDER BY user_id;
