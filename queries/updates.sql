-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Update requests are written by the app and carried out by the updater (pihole-rbac updater), which runs as root.

-- name: InsertUpdateRequest :one
INSERT INTO update_requests (requested_at, requested_by, requested_by_name, target_version)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: ListUpdateRequests :many
-- The newest requests first.
SELECT * FROM update_requests ORDER BY id DESC LIMIT ?;

-- name: CountActiveUpdateRequests :one
SELECT count(*) FROM update_requests WHERE status IN ('pending', 'running');

-- name: FailStaleUpdateRequests :execrows
-- A pending request the updater never picked up (its units aren't installed, say), or a running one it never
-- finished, would otherwise block every later request.
UPDATE update_requests
SET status = 'failed', finished_at = sqlc.arg(now), log = log || sqlc.arg(message)
WHERE (status = 'pending' AND requested_at < sqlc.arg(pending_before))
   OR (status = 'running' AND requested_at < sqlc.arg(running_before));

-- name: ListFinishedUpdateRequestsAfter :many
-- The finished requests the app hasn't announced yet, oldest first.
SELECT * FROM update_requests
WHERE id > ? AND status IN ('done', 'failed', 'rolled_back')
ORDER BY id;

-- The updater's side.

-- name: ClaimUpdateRequest :one
-- The oldest pending request, now marked running. sql.ErrNoRows when there is none.
UPDATE update_requests SET status = 'running'
WHERE id = (SELECT id FROM update_requests WHERE status = 'pending' ORDER BY id LIMIT 1)
RETURNING *;

-- name: AppendUpdateLog :exec
UPDATE update_requests SET log = log || sqlc.arg(line) WHERE id = sqlc.arg(id);

-- name: FinishUpdateRequest :execrows
-- Only a running request: one the app has meanwhile marked failed as stale stays so.
UPDATE update_requests SET status = sqlc.arg(status), finished_at = sqlc.arg(finished_at)
WHERE id = sqlc.arg(id) AND status = 'running';
