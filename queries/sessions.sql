-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: CreateSession :exec
INSERT INTO sessions (id_hash, public_id, user_id, created_at, expires_at, last_seen_at, roles_checked_at, ip, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: AddSessionRole :exec
INSERT INTO session_roles (session_id_hash, role_id) VALUES (?, ?);

-- name: GetSessionWithUser :one
SELECT s.id_hash, s.public_id, s.user_id, s.created_at, s.expires_at, s.last_seen_at, s.roles_checked_at,
       s.ip, s.user_agent, u.username, u.source, u.disabled
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.id_hash = ?;

-- name: ListSessionRoleIDs :many
SELECT role_id FROM session_roles WHERE session_id_hash = ? ORDER BY role_id;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = ?;

-- name: DeleteUserSessions :execrows
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= sqlc.arg(now) OR last_seen_at <= sqlc.arg(idle_cutoff);
