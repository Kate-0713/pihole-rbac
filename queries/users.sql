-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: CreateLocalUser :one
INSERT INTO users (username, source, password_hash, created_at)
VALUES (?, 'local', ?, ?)
RETURNING *;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = ?;

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: SetUserLastLogin :exec
UPDATE users SET last_login_at = ? WHERE id = ?;

-- name: ListUserRoleIDs :many
SELECT role_id FROM user_roles WHERE user_id = ? ORDER BY role_id;

-- name: SetUserDisabled :exec
UPDATE users SET disabled = ? WHERE id = ?;

-- name: AddUserRole :exec
INSERT INTO user_roles (user_id, role_id) VALUES (?, ?);

-- name: CreateLDAPUser :one
INSERT INTO users (username, source, ldap_dn, created_at)
VALUES (?, 'ldap', ?, ?)
RETURNING id;

-- name: SetUserLDAPDN :exec
UPDATE users SET ldap_dn = ? WHERE id = ?;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: DeleteUserRoles :exec
DELETE FROM user_roles WHERE user_id = ?;

-- Invariant 2: enabled local users holding the builtin admin role.
-- name: CountEnabledLocalAdmins :one
SELECT COUNT(*) FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE r.builtin = 1 AND u.source = 'local' AND u.disabled = 0;
