-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Personal API tokens: a token belongs to a user and carries its own grants, which are intersected on every request
-- with what the user holds at that moment. tokens.use is needed to create a token and for one to work, and only the
-- builtin admin role gets it here, so after upgrading nobody else can until an admin grants it.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- Scope all grants on the builtin role are allowed by role_grants_builtin_insert.
INSERT INTO role_grants (role_id, permission, scope_type)
SELECT id, 'tokens.use', 'all' FROM roles WHERE builtin = 1;

-- A token is prt_<public_id>_<secret>. Only the SHA-256 of the secret is kept. A name is unique per user among
-- tokens that aren't revoked, so revoking one frees its name. The app keeps expires_at within a year of created_at.
CREATE TABLE api_tokens (
    id           INTEGER PRIMARY KEY,
    public_id    TEXT    NOT NULL UNIQUE CHECK (length(public_id) = 16),
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL CHECK (name <> ''),
    secret_hash  BLOB    NOT NULL CHECK (length(secret_hash) = 32),
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    last_used_ip TEXT    NOT NULL DEFAULT '',
    revoked_at   INTEGER,
    CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX api_tokens_user_name ON api_tokens (user_id, name) WHERE revoked_at IS NULL;
CREATE INDEX api_tokens_user ON api_tokens (user_id);

-- A token's own grants, with the same checks as role_grants. instance_id and group_id have no ON DELETE: deleting an
-- instance or group that a live token's grant names is refused, as it is for roles, and the delete removes the grants
-- of revoked and expired tokens itself.
CREATE TABLE api_token_grants (
    id          INTEGER PRIMARY KEY,
    token_id    INTEGER NOT NULL REFERENCES api_tokens (id) ON DELETE CASCADE,
    permission  TEXT    NOT NULL CHECK (permission <> ''),
    scope_type  TEXT    NOT NULL CHECK (scope_type IN ('all', 'group', 'instance')),
    instance_id INTEGER REFERENCES instances (id),
    group_id    INTEGER REFERENCES instance_groups (id),
    CHECK ((scope_type = 'all'      AND instance_id IS NULL     AND group_id IS NULL)
        OR (scope_type = 'instance' AND instance_id IS NOT NULL AND group_id IS NULL)
        OR (scope_type = 'group'    AND group_id IS NOT NULL    AND instance_id IS NULL))
);

-- SQLite treats NULLs as distinct in UNIQUE constraints, hence the expression index, as for role_grants.
CREATE UNIQUE INDEX api_token_grants_unique
    ON api_token_grants (token_id, permission, scope_type, ifnull(instance_id, 0), ifnull(group_id, 0));
CREATE INDEX api_token_grants_instance ON api_token_grants (instance_id);
CREATE INDEX api_token_grants_group ON api_token_grants (group_id);

-- +goose Down

DROP TABLE api_token_grants;
DROP TABLE api_tokens;

DELETE FROM role_grants WHERE permission = 'tokens.use' AND role_id NOT IN (SELECT id FROM roles WHERE builtin = 1);

-- The builtin role's grants are protected by role_grants_builtin_no_delete, so the trigger is dropped around the
-- delete and recreated exactly as 00001 defines it.
DROP TRIGGER role_grants_builtin_no_delete;

DELETE FROM role_grants WHERE permission = 'tokens.use';

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd
