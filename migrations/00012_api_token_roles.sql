-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- API tokens for LDAP users. An LDAP user's roles come from their directory groups, so a token of theirs holds role
-- IDs as a session does, and roles_checked_at says when the LDAP recheck last confirmed them. A token whose roles
-- haven't been confirmed for longer than the recheck interval plus the grace period is suspended. A local user's
-- tokens keep both empty: their roles are user_roles.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

ALTER TABLE api_tokens ADD COLUMN roles_checked_at INTEGER;

CREATE TABLE api_token_roles (
    token_id INTEGER NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    role_id  INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, role_id)
);

CREATE INDEX api_token_roles_role ON api_token_roles (role_id);

-- +goose Down

DROP TABLE api_token_roles;
ALTER TABLE api_tokens DROP COLUMN roles_checked_at;
