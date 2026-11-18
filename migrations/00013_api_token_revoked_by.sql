-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Who revoked an API token, so the token lists can say: its owner (self), an admin, or the LDAP recheck, which also
-- records why (no role maps to the user's groups, or they are gone from the directory). Tokens revoked before this
-- migration keep both NULL and are shown as revoked with no more said.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

ALTER TABLE api_tokens ADD COLUMN revoked_by TEXT CHECK (revoked_by IN ('self', 'admin', 'recheck'));
ALTER TABLE api_tokens ADD COLUMN revoked_reason TEXT CHECK (revoked_reason <> '');

-- +goose Down

ALTER TABLE api_tokens DROP COLUMN revoked_reason;
ALTER TABLE api_tokens DROP COLUMN revoked_by;
