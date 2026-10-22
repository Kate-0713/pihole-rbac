-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: GetRoleByName :one
SELECT * FROM roles WHERE name = ?;

-- name: ListGrantsForRole :many
SELECT * FROM role_grants
WHERE role_id = ?
ORDER BY permission, scope_type, instance_id, group_id;
