-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: InsertAudit :one
INSERT INTO audit_log (at, user_id, username, action, target, instance_id, instance_name, result, detail, ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: GetAudit :one
SELECT * FROM audit_log WHERE id = ?;
