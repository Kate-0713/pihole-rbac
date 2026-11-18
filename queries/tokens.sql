-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- A token is live while it is neither revoked nor expired. A live token whose owner no longer holds tokens.use, or
-- is disabled, is refused on use but still live: it works again if they get it back before it expires.

-- roles_checked_at is set for an LDAP user's token, from the session that makes it, and NULL for a local user's.
-- name: InsertAPIToken :one
INSERT INTO api_tokens (public_id, user_id, name, secret_hash, created_at, expires_at, roles_checked_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: AddAPITokenRole :exec
INSERT INTO api_token_roles (token_id, role_id) VALUES (?, ?);

-- name: ListAPITokenRoleIDs :many
SELECT role_id FROM api_token_roles WHERE token_id = ? ORDER BY role_id;

-- Makes the live tokens holding a role due for the LDAP recheck at once, as MarkRoleSessionsDue does for sessions,
-- when a group mapping to the role is removed. Only LDAP users' tokens hold roles.
-- name: MarkRoleTokensDue :execrows
UPDATE api_tokens SET roles_checked_at = MIN(roles_checked_at, CAST(sqlc.arg(due) AS INTEGER))
WHERE revoked_at IS NULL AND roles_checked_at IS NOT NULL
  AND id IN (SELECT token_id FROM api_token_roles WHERE role_id = sqlc.arg(role_id));

-- name: InsertAPITokenGrant :exec
INSERT INTO api_token_grants (token_id, permission, scope_type, instance_id, group_id) VALUES (?, ?, ?, ?, ?);

-- name: CountLiveAPITokensForUser :one
SELECT COUNT(*) FROM api_tokens
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL AND expires_at > sqlc.arg(now);

-- name: GetAPIToken :one
SELECT t.*, u.username, u.source AS owner_source, u.disabled AS owner_disabled FROM api_tokens t JOIN users u ON u.id = t.user_id
WHERE t.public_id = ?;

-- name: ListAPITokensForUser :many
SELECT t.*, u.username, u.source AS owner_source, u.disabled AS owner_disabled FROM api_tokens t JOIN users u ON u.id = t.user_id
WHERE t.user_id = ?
ORDER BY t.created_at DESC, t.id DESC;

-- name: ListAllAPITokens :many
SELECT t.*, u.username, u.source AS owner_source, u.disabled AS owner_disabled FROM api_tokens t JOIN users u ON u.id = t.user_id
ORDER BY u.username, t.created_at DESC, t.id DESC;

-- name: ListAPITokenGrants :many
SELECT * FROM api_token_grants
WHERE token_id IN (sqlc.slice('token_ids'))
ORDER BY token_id, permission, scope_type, instance_id, group_id;

-- Revokes a token, recording who did (self, admin or recheck) and, for the recheck, why. No row changes if it was
-- revoked already.
-- name: RevokeAPIToken :execrows
UPDATE api_tokens
SET revoked_at = sqlc.arg(revoked_at), revoked_by = sqlc.arg(revoked_by), revoked_reason = sqlc.narg(revoked_reason)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- Deletes tokens revoked or expired before the cutoff. Their grants go with them.
-- name: PruneAPITokens :execrows
DELETE FROM api_tokens WHERE revoked_at < sqlc.arg(cutoff) OR expires_at < sqlc.arg(cutoff);

-- The live tokens with a grant on an instance, so a refused delete can say which.
-- name: ListLiveAPITokensOnInstance :many
SELECT DISTINCT u.username, t.name FROM api_token_grants g
JOIN api_tokens t ON t.id = g.token_id JOIN users u ON u.id = t.user_id
WHERE g.instance_id = sqlc.arg(instance_id) AND t.revoked_at IS NULL AND t.expires_at > sqlc.arg(now)
ORDER BY u.username, t.name;

-- name: ListLiveAPITokensOnGroup :many
SELECT DISTINCT u.username, t.name FROM api_token_grants g
JOIN api_tokens t ON t.id = g.token_id JOIN users u ON u.id = t.user_id
WHERE g.group_id = sqlc.arg(group_id) AND t.revoked_at IS NULL AND t.expires_at > sqlc.arg(now)
ORDER BY u.username, t.name;

-- Live tokens holding any of the given permissions on a group, for the mirrored-to-independent check. The slice is
-- the last argument: sqlc numbers any argument after a slice wrongly.
-- name: ListLiveAPITokensWithGrantsOnGroup :many
SELECT DISTINCT u.username, t.name FROM api_token_grants g
JOIN api_tokens t ON t.id = g.token_id JOIN users u ON u.id = t.user_id
WHERE g.group_id = sqlc.arg(group_id) AND t.revoked_at IS NULL AND t.expires_at > sqlc.arg(now)
  AND g.permission IN (sqlc.slice('permissions'))
ORDER BY u.username, t.name;

-- The grants of revoked and expired tokens on an instance or group, which would otherwise hold up its delete.
-- name: DeleteDeadAPITokenGrantsOnInstance :exec
DELETE FROM api_token_grants
WHERE instance_id = sqlc.arg(instance_id)
  AND token_id IN (SELECT id FROM api_tokens WHERE revoked_at IS NOT NULL OR expires_at <= sqlc.arg(now));

-- name: DeleteDeadAPITokenGrantsOnGroup :exec
DELETE FROM api_token_grants
WHERE group_id = sqlc.arg(group_id)
  AND token_id IN (SELECT id FROM api_tokens WHERE revoked_at IS NOT NULL OR expires_at <= sqlc.arg(now));

-- A token as a request authenticates with it, with what the gate needs of its owner.
-- name: GetAPITokenForAuth :one
SELECT t.id, t.public_id, t.user_id, t.name, t.secret_hash, t.expires_at, t.revoked_at, t.roles_checked_at,
       u.username, u.source, u.disabled
FROM api_tokens t JOIN users u ON u.id = t.user_id
WHERE t.public_id = ?;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = sqlc.arg(last_used_at), last_used_ip = sqlc.arg(last_used_ip) WHERE id = sqlc.arg(id);

-- An LDAP user's live tokens, for the recheck.
-- name: ListLiveLDAPTokensForUser :many
SELECT id, public_id, name FROM api_tokens
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL AND expires_at > sqlc.arg(now) AND roles_checked_at IS NOT NULL
ORDER BY id;

-- The roles an LDAP user's live tokens hold between them, for the recheck to compare.
-- name: ListLiveLDAPTokenRoleIDsForUser :many
SELECT DISTINCT r.role_id FROM api_token_roles r JOIN api_tokens t ON t.id = r.token_id
WHERE t.user_id = sqlc.arg(user_id) AND t.revoked_at IS NULL AND t.expires_at > sqlc.arg(now)
ORDER BY r.role_id;

-- name: ClearAPITokenRoles :exec
DELETE FROM api_token_roles WHERE token_id = ?;

-- Records a successful recheck on an LDAP user's live tokens.
-- name: SetUserTokensRolesChecked :exec
UPDATE api_tokens SET roles_checked_at = sqlc.arg(roles_checked_at)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL AND roles_checked_at IS NOT NULL;
