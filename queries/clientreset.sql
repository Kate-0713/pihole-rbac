-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: ListClientResetRules :many
-- Every rule with its instance's or group's name, instances first, then by name and prefix.
SELECT r.id, r.instance_id, r.group_id, r.comment_prefix, r.group_match, r.target_groups,
       COALESCE(i.name, '') AS instance_name, COALESCE(g.name, '') AS group_name, COALESCE(g.mode, '') AS group_mode
FROM client_reset_targets r
LEFT JOIN instances i ON i.id = r.instance_id
LEFT JOIN instance_groups g ON g.id = r.group_id
ORDER BY r.group_id IS NOT NULL, COALESCE(i.name, g.name) COLLATE NOCASE, r.comment_prefix;

-- name: ListClientResetRulesFor :many
-- The rules of one instance or group, by prefix.
SELECT id, instance_id, group_id, comment_prefix, group_match, target_groups FROM client_reset_targets
WHERE instance_id = sqlc.narg(instance_id) OR group_id = sqlc.narg(group_id)
ORDER BY comment_prefix;

-- name: DeleteAllClientResetRules :exec
DELETE FROM client_reset_targets;

-- name: AddClientResetRule :exec
INSERT INTO client_reset_targets (instance_id, group_id, comment_prefix, group_match, target_groups)
VALUES (?, ?, ?, ?, ?);

-- name: StartClientResetRun :one
-- Fails on the one-running index while another run hasn't finished.
INSERT INTO client_reset_runs (started_at, trigger, user_id, username, target, instance_id, group_id, target_name, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')
RETURNING id;

-- name: FinishClientResetRun :exec
UPDATE client_reset_runs SET finished_at = ?, status = ?, summary = ? WHERE id = ? AND status = 'running';

-- name: FailInterruptedClientResetRuns :execrows
-- Runs left running by a process that stopped: nothing is running them any more.
UPDATE client_reset_runs SET finished_at = sqlc.arg(finished_at), status = 'failed', summary = sqlc.arg(summary)
WHERE status = 'running';

-- name: GetClientResetRun :one
SELECT * FROM client_reset_runs WHERE id = ?;

-- name: ListClientResetRuns :many
-- Newest first, optionally for one target, paged by ID.
SELECT * FROM client_reset_runs
WHERE (CAST(sqlc.arg(target) AS TEXT) = '' OR target = sqlc.arg(target))
  AND (CAST(sqlc.arg(before_id) AS INTEGER) = 0 OR id < sqlc.arg(before_id))
ORDER BY id DESC
LIMIT sqlc.arg(row_limit);

-- name: DeleteClientResetRunsBefore :execrows
-- Finished runs older than the cutoff; one still running is never removed.
DELETE FROM client_reset_runs WHERE status <> 'running' AND started_at < ?;
