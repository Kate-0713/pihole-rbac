-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: ListLogDestinations :many
SELECT * FROM log_destinations ORDER BY name COLLATE NOCASE, id;

-- name: GetLogDestination :one
SELECT * FROM log_destinations WHERE id = ?;

-- name: CreateLogDestination :one
INSERT INTO log_destinations (name, host, port, transport, tls_mode, ca_file, enabled, created_at, created_by, updated_at, updated_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateLogDestination :exec
UPDATE log_destinations
SET name = ?, host = ?, port = ?, transport = ?, tls_mode = ?, ca_file = ?, enabled = ?, updated_at = ?, updated_by = ?
WHERE id = ?;

-- name: DeleteLogDestination :exec
DELETE FROM log_destinations WHERE id = ?;

-- name: LogDestinationNameTaken :one
-- Whether another destination has this name, ignoring case.
SELECT EXISTS (SELECT 1 FROM log_destinations WHERE name = ? COLLATE NOCASE AND id <> ?);

-- name: GetLogCursor :one
SELECT * FROM log_destination_cursors WHERE destination_id = ?;

-- name: ListLogCursors :many
SELECT * FROM log_destination_cursors ORDER BY destination_id;

-- name: SetLogCursor :exec
INSERT INTO log_destination_cursors (destination_id, last_id, updated_at) VALUES (?, ?, ?)
ON CONFLICT (destination_id) DO UPDATE SET last_id = excluded.last_id, updated_at = excluded.updated_at;

-- name: ListAuditAfter :many
-- The next rows to forward, oldest first: those after the last ID a destination was sent.
SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT ?;

-- name: NewestAuditID :one
-- The ID a new destination starts at, so it sends new events only. 0 when the table is empty.
SELECT CAST(COALESCE(MAX(id), 0) AS INTEGER) FROM audit_log;

-- name: OldestAuditID :one
-- The oldest row left after pruning, to work out how many rows a destination never got. 0 when the table is empty.
SELECT CAST(COALESCE(MIN(id), 0) AS INTEGER) FROM audit_log;

-- name: CountAuditAfter :one
-- How many rows a destination has yet to be sent.
SELECT count(*) FROM audit_log WHERE id > ?;

-- name: AdvanceLogCursor :exec
-- Moves a cursor forward and never back, so a delayed write can't make a destination send rows again.
-- Every parameter is named: sqlc numbers a named parameter that comes before bare ones wrongly, which left the
-- statement expecting more arguments than it was given.
UPDATE log_destination_cursors
SET last_id = max(last_id, CAST(sqlc.arg(last_id) AS INTEGER)), updated_at = sqlc.arg(updated_at)
WHERE destination_id = sqlc.arg(destination_id);
