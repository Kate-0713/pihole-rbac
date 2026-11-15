-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: InsertAudit :one
INSERT INTO audit_log (at, user_id, username, action, target, instance_id, instance_name, result, detail, ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: GetAudit :one
SELECT * FROM audit_log WHERE id = ?;

-- name: ListRecentAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT ?;

-- name: ListAudit :many
-- Newest first, filtered; each filter is skipped when empty or zero. actions is a JSON array of action names ('[]'
-- for any). from_at is inclusive and to_at exclusive. before_id pages: rows older than the previous page's last.
SELECT * FROM audit_log
WHERE (CAST(sqlc.arg(username) AS TEXT) = '' OR username = sqlc.arg(username))
  AND (CAST(sqlc.arg(actions) AS TEXT) = '[]'
       OR action IN (SELECT value FROM json_each(CAST(sqlc.arg(actions) AS TEXT))))
  AND (CAST(sqlc.arg(target) AS TEXT) = '' OR target = sqlc.arg(target))
  AND (CAST(sqlc.arg(instance_id) AS INTEGER) = 0 OR instance_id = sqlc.arg(instance_id))
  AND (CAST(sqlc.arg(result) AS TEXT) = '' OR result = sqlc.arg(result))
  AND (CAST(sqlc.arg(from_at) AS INTEGER) = 0 OR at >= sqlc.arg(from_at))
  AND (CAST(sqlc.arg(to_at) AS INTEGER) = 0 OR at < sqlc.arg(to_at))
  AND (CAST(sqlc.arg(before_id) AS INTEGER) = 0 OR id < sqlc.arg(before_id))
ORDER BY id DESC
LIMIT sqlc.arg(row_limit);

-- name: DeleteAuditBefore :execrows
DELETE FROM audit_log WHERE at < ?;

-- name: ListLocalDNSChanges :many
-- The newest local DNS changes made through the app on an instance, for each record's latest reason: the action,
-- the record's key, the reason given and who and when. Rows recorded as failures don't count, except a change that
-- added the new record before failing to delete the old one.
SELECT action,
       CAST(COALESCE(json_extract(detail, '$.key'), '') AS TEXT)    AS record_key,
       CAST(COALESCE(json_extract(detail, '$.reason'), '') AS TEXT) AS reason,
       username, at
FROM audit_log
WHERE instance_id = sqlc.arg(instance_id)
  AND (result = 'success' OR json_extract(detail, '$.added') = 1)
  AND action IN ('dnsrecord_add', 'dnsrecord_update', 'dnsrecord_delete', 'cname_add', 'cname_update', 'cname_delete')
ORDER BY id DESC
LIMIT sqlc.arg(row_limit);
