-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- localdns.view and localdns.edit: reading and changing a Pi-hole's local DNS records and CNAMEs. Only the builtin
-- admin role gets them, so after upgrading nobody else can until an admin grants them.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- Scope all grants on the builtin role are allowed by role_grants_builtin_insert.
INSERT INTO role_grants (role_id, permission, scope_type)
SELECT id, p.permission, 'all' FROM roles
CROSS JOIN (SELECT 'localdns.view' AS permission UNION ALL SELECT 'localdns.edit') AS p
WHERE builtin = 1;

-- +goose Down

DELETE FROM role_grants
WHERE permission IN ('localdns.view', 'localdns.edit')
  AND role_id NOT IN (SELECT id FROM roles WHERE builtin = 1);

-- The builtin role's grants are protected by role_grants_builtin_no_delete, so the trigger is dropped around the
-- delete and recreated exactly as 00001 defines it.
DROP TRIGGER role_grants_builtin_no_delete;

DELETE FROM role_grants WHERE permission IN ('localdns.view', 'localdns.edit');

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd
