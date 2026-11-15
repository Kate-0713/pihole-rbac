-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: ListSchedules :many
-- Every schedule with its instance's or group's name, instances first, then by target and name.
SELECT s.*, COALESCE(i.name, '') AS instance_name, COALESCE(g.name, '') AS group_name
FROM schedules s
LEFT JOIN instances i ON i.id = s.instance_id
LEFT JOIN instance_groups g ON g.id = s.group_id
ORDER BY s.group_id IS NOT NULL, COALESCE(i.name, g.name) COLLATE NOCASE, s.name COLLATE NOCASE;

-- name: GetSchedule :one
SELECT s.*, COALESCE(i.name, '') AS instance_name, COALESCE(g.name, '') AS group_name
FROM schedules s
LEFT JOIN instances i ON i.id = s.instance_id
LEFT JOIN instance_groups g ON g.id = s.group_id
WHERE s.id = ?;

-- name: CreateSchedule :one
INSERT INTO schedules (name, instance_id, group_id, kind, pihole_group, repeat, days, start_min, end_min, end_days,
                       time_zone, starts_at, ends_at, active_from, enabled, created_at, created_by, updated_at,
                       updated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateSchedule :exec
-- A saved change: the schedule acts from its next edge after active_from, with no results yet.
UPDATE schedules
SET name = ?, pihole_group = ?, repeat = ?, days = ?, start_min = ?, end_min = ?, end_days = ?, time_zone = ?,
    starts_at = ?, ends_at = ?, active_from = ?, enabled = ?, last_results = '{}', updated_at = ?, updated_by = ?
WHERE id = ?;

-- name: DeleteSchedule :exec
DELETE FROM schedules WHERE id = ?;

-- name: RecordScheduleEdge :execrows
-- The scheduler applied an edge, or retried one: what it was, each instance's result, and whether a one-off
-- schedule is now finished. Nothing changes when the schedule was saved since the scheduler read it (updated_at
-- differs): the results are for a version that no longer exists.
UPDATE schedules SET last_edge_at = ?, last_edge = ?, last_results = ?, finished_at = ?
WHERE id = sqlc.arg(id) AND updated_at = sqlc.arg(updated_at);

-- name: RenameScheduleGroup :exec
UPDATE schedules SET pihole_group = ? WHERE id = ?;
