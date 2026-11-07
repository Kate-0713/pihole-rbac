-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- blocking.indefinite: turning blocking off with no timer. Only the builtin admin role gets it. Other roles that
-- hold blocking.toggle are deliberately left without it, so after upgrading they can only turn blocking off for a
-- set time until an admin grants it.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- A scope all grant on the builtin role is allowed by role_grants_builtin_insert.
INSERT INTO role_grants (role_id, permission, scope_type)
SELECT id, 'blocking.indefinite', 'all' FROM roles WHERE builtin = 1;

-- +goose Down

DELETE FROM role_grants
WHERE permission = 'blocking.indefinite' AND role_id NOT IN (SELECT id FROM roles WHERE builtin = 1);

-- The builtin role's grant is protected by role_grants_builtin_no_delete, so the trigger is dropped around the delete
-- and recreated exactly as 00001 defines it.
DROP TRIGGER role_grants_builtin_no_delete;

DELETE FROM role_grants WHERE permission = 'blocking.indefinite';

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd
