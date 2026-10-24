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

-- name: DeleteUserSessionsExcept :execrows
DELETE FROM sessions WHERE user_id = ? AND public_id <> ?;

-- The roles held by any of a user's sessions. For LDAP users this is the only record of their roles.
-- name: ListSessionRoleIDsForUser :many
SELECT DISTINCT sr.role_id FROM session_roles sr JOIN sessions s ON s.id_hash = sr.session_id_hash
WHERE s.user_id = ?
ORDER BY sr.role_id;

-- name: ClearSessionRolesForUser :exec
DELETE FROM session_roles WHERE session_id_hash IN (SELECT id_hash FROM sessions WHERE user_id = ?);

-- name: AddSessionRoleForUser :exec
INSERT INTO session_roles (session_id_hash, role_id)
SELECT id_hash, sqlc.arg(role_id) FROM sessions WHERE user_id = sqlc.arg(user_id);

-- Makes the LDAP sessions holding a role due for recheck: roles_checked_at becomes at most due, which the caller
-- sets to one recheck interval ago. It never moves later, so a session's grace period can't be extended.
-- name: MarkRoleSessionsDue :execrows
UPDATE sessions SET roles_checked_at = MIN(roles_checked_at, CAST(sqlc.arg(due) AS INTEGER))
WHERE user_id IN (SELECT id FROM users WHERE source = 'ldap')
  AND id_hash IN (SELECT session_id_hash FROM session_roles WHERE role_id = sqlc.arg(role_id));

-- name: ListUserSessions :many
SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at, public_id;

-- The LDAP users with at least one session whose roles were last checked at or before cutoff.
-- name: ListLDAPUsersDueForRecheck :many
SELECT DISTINCT u.id, u.username, u.disabled, u.ldap_dn
FROM users u
JOIN sessions s ON s.user_id = u.id
WHERE u.source = 'ldap' AND s.roles_checked_at <= sqlc.arg(cutoff)
ORDER BY u.id;

-- name: SetUserSessionsRolesChecked :exec
UPDATE sessions SET roles_checked_at = ? WHERE user_id = ?;

-- Active sessions, newest first, for the sessions pages: not past their end, not idle, and of an enabled user.
-- user_id narrows them to one user. The cursor is the (created_at, public_id) of the last row of the previous page.
-- name: ListActiveSessions :many
SELECT s.public_id, s.user_id, s.created_at, s.expires_at, s.last_seen_at, s.ip, s.user_agent, u.username, u.source
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.expires_at > sqlc.arg(now)
  AND s.last_seen_at > sqlc.arg(idle_cutoff)
  AND u.disabled = 0
  AND (CAST(sqlc.arg(user_id) AS INTEGER) = 0 OR s.user_id = sqlc.arg(user_id))
  AND (CAST(sqlc.arg(after_created) AS INTEGER) = 0
       OR s.created_at < sqlc.arg(after_created)
       OR (s.created_at = sqlc.arg(after_created) AND s.public_id < sqlc.arg(after_public_id)))
ORDER BY s.created_at DESC, s.public_id DESC
LIMIT sqlc.arg(row_limit);

-- name: GetSessionByPublicID :one
SELECT s.public_id, s.user_id, u.username
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.public_id = ?;

-- name: DeleteSessionByPublicID :execrows
DELETE FROM sessions WHERE public_id = ?;
