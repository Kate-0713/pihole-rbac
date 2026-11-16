-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Two-factor login (TOTP): a user's secret and recovery codes, and who must use it. No permission changes: a role's
-- requirement is set with roles.manage and a user's own setting with users.manage.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- A user's TOTP secret, AES-256-GCM under the master key and bound to the row (secrets.AAD("user_totp", user_id)).
-- It has its own table rather than columns on users, so reading a user never carries the ciphertext, and so the
-- secret columns can be NOT NULL. enabled_at is NULL while the secret waits for its first correct code, and such a
-- row doesn't ask for a code at login. last_step is the time step of the last code accepted, so a code can't be used
-- twice.
CREATE TABLE user_totp (
    user_id           INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_ciphertext BLOB    NOT NULL CHECK (length(secret_ciphertext) > 0),
    secret_nonce      BLOB    NOT NULL CHECK (length(secret_nonce) = 12),
    secret_key_id     TEXT    NOT NULL CHECK (secret_key_id <> ''),
    created_at        INTEGER NOT NULL,
    enabled_at        INTEGER,
    last_step         INTEGER NOT NULL DEFAULT 0 CHECK (last_step >= 0)
);

-- Single-use recovery codes, stored as SHA-256 of the code. They belong to the secret, so removing a user's TOTP
-- removes them.
CREATE TABLE user_recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES user_totp (user_id) ON DELETE CASCADE,
    code_hash BLOB    NOT NULL CHECK (length(code_hash) = 32),
    used_at   INTEGER,
    UNIQUE (user_id, code_hash)
);

-- The roles whose holders must use TOTP. A row means required. It is its own table rather than a column on roles
-- because roles_builtin_no_update refuses every update of the builtin admin role, which can be listed here like any
-- other.
CREATE TABLE role_totp_required (
    role_id INTEGER PRIMARY KEY REFERENCES roles (id) ON DELETE CASCADE,
    set_at  INTEGER NOT NULL,
    set_by  TEXT    NOT NULL DEFAULT ''
);

-- A user's own setting, which wins over their roles': required, or exempt. No row means the roles decide.
CREATE TABLE user_totp_policy (
    user_id INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    policy  TEXT    NOT NULL CHECK (policy IN ('required', 'exempt')),
    set_at  INTEGER NOT NULL,
    set_by  TEXT    NOT NULL DEFAULT ''
);

-- +goose Down

DROP TABLE user_totp_policy;
DROP TABLE role_totp_required;
DROP TABLE user_recovery_codes;
DROP TABLE user_totp;
