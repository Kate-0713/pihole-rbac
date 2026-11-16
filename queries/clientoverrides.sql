-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: CreateClientOverride :one
INSERT INTO client_group_overrides (instance_id, group_id, client, starts_at, ends_at, reason, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: CreateClientOverrideMember :one
INSERT INTO client_group_override_members (override_id, instance_id, client, original_groups, override_groups)
VALUES (?, ?, ?, ?, ?)
RETURNING id;

-- name: ListActiveOverrideMembers :many
-- Every member of an active override that hasn't settled, with where it was set: these are the Pi-hole group
-- references of the temporary changes.
SELECT m.id, m.override_id, m.instance_id, m.client, m.original_groups, m.override_groups,
       i.name AS instance_name, o.instance_id AS target_instance_id, o.group_id AS target_group_id,
       COALESCE(ti.name, tg.name, '') AS target_name
FROM client_group_override_members m
JOIN client_group_overrides o ON o.id = m.override_id
JOIN instances i ON i.id = m.instance_id
LEFT JOIN instances ti ON ti.id = o.instance_id
LEFT JOIN instance_groups tg ON tg.id = o.group_id
WHERE m.active = 1
ORDER BY i.name COLLATE NOCASE, m.client, m.id;

-- name: UpdateOverrideMemberGroups :exec
UPDATE client_group_override_members SET original_groups = ?, override_groups = ? WHERE id = ?;

-- name: GetClientOverride :one
SELECT o.*, COALESCE(ti.name, tg.name, '') AS target_name
FROM client_group_overrides o
LEFT JOIN instances ti ON ti.id = o.instance_id
LEFT JOIN instance_groups tg ON tg.id = o.group_id
WHERE o.id = ?;

-- name: ListClientOverridesOnTarget :many
-- The target's active overrides, and the ones that finished since the cutoff, newest first.
SELECT o.*, COALESCE(ti.name, tg.name, '') AS target_name
FROM client_group_overrides o
LEFT JOIN instances ti ON ti.id = o.instance_id
LEFT JOIN instance_groups tg ON tg.id = o.group_id
WHERE ((sqlc.narg(instance_id) IS NOT NULL AND o.instance_id = sqlc.narg(instance_id))
    OR (sqlc.narg(group_id) IS NOT NULL AND o.group_id = sqlc.narg(group_id)))
  AND (o.status = 'active' OR o.finished_at >= sqlc.arg(since))
ORDER BY o.status <> 'active', o.ends_at DESC, o.id DESC
LIMIT 100;

-- name: ListClientOverridesCovering :many
-- The active overrides, made through any mirrored group, that have a member on this instance.
SELECT DISTINCT o.*, COALESCE(tg.name, '') AS target_name
FROM client_group_overrides o
JOIN client_group_override_members m ON m.override_id = o.id
LEFT JOIN instance_groups tg ON tg.id = o.group_id
WHERE o.group_id IS NOT NULL AND o.status = 'active' AND m.instance_id = ?
ORDER BY o.ends_at, o.id;

-- name: ListActiveClientOverrides :many
SELECT o.*, COALESCE(ti.name, tg.name, '') AS target_name
FROM client_group_overrides o
LEFT JOIN instances ti ON ti.id = o.instance_id
LEFT JOIN instance_groups tg ON tg.id = o.group_id
WHERE o.status = 'active'
ORDER BY o.ends_at, o.id;

-- name: ListOverrideMembers :many
SELECT m.*, i.name AS instance_name
FROM client_group_override_members m
JOIN instances i ON i.id = m.instance_id
WHERE m.override_id = ?
ORDER BY i.name COLLATE NOCASE, m.id;

-- name: SetOverrideEnd :exec
UPDATE client_group_overrides SET ends_at = ?, ended_by = ?, ended_at = ? WHERE id = ? AND status = 'active';

-- name: SettleOverrideMember :exec
UPDATE client_group_override_members
SET active = ?, revert_status = ?, revert_code = ?, revert_details = ?, attempts = ?, reverted_at = ?
WHERE id = ?;

-- name: FinishClientOverride :exec
UPDATE client_group_overrides SET status = ?, finished_at = ? WHERE id = ? AND status = 'active';

-- name: ReopenClientOverride :exec
UPDATE client_group_overrides SET status = 'active', finished_at = NULL WHERE id = ? AND status = 'failed';

-- name: ReopenOverrideMember :exec
UPDATE client_group_override_members
SET active = 1, revert_status = 'pending', revert_code = NULL, attempts = 0
WHERE id = ? AND revert_status = 'given_up';

-- name: DeleteClientOverride :exec
DELETE FROM client_group_overrides WHERE id = ?;

-- name: DeleteOverrideMember :exec
DELETE FROM client_group_override_members WHERE override_id = ? AND instance_id = ?;

-- name: ListActiveOverrideClientsOnInstance :many
-- The clients with an active override on this instance, for client reset to leave alone.
SELECT m.client, m.override_id FROM client_group_override_members m WHERE m.instance_id = ? AND m.active = 1;

-- name: ListActiveOverridesBlockingInstance :many
-- The active overrides that stop an instance being deleted: made on it, or through a group it belongs to.
SELECT DISTINCT o.id, o.client FROM client_group_overrides o
LEFT JOIN client_group_override_members m ON m.override_id = o.id
WHERE o.status = 'active' AND (o.instance_id = ? OR m.instance_id = ?)
ORDER BY o.id;

-- name: ListActiveOverridesOnGroup :many
SELECT id, client FROM client_group_overrides WHERE group_id = ? AND status = 'active' ORDER BY id;

-- name: DeleteClientOverridesBefore :execrows
DELETE FROM client_group_overrides WHERE status <> 'active' AND finished_at < ?;

-- name: SetOverrideEndOnly :exec
UPDATE client_group_overrides SET ends_at = ? WHERE id = ? AND status = 'active';
