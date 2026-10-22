-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Initial schema. Until v2.0.0 ships this file is edited in place.
-- After that, migrations will be append-only.
--
-- Conventions
--   timestamps: INTEGER Unix milliseconds, UTC (store.Millis / store.FromMillis)
--   booleans:   BOOLEAN with a CHECK (x IN (0, 1))
--   JSON:       TEXT with CHECK (json_valid(x))
--   An instance-or-group reference is two nullable FK columns plus a CHECK, so
--   deleting anything still referenced is blocked.
--   Blocking FKs use the default NO ACTION, not RESTRICT. Both block the delete,
--   but SQLite reports RESTRICT as SQLITE_CONSTRAINT_TRIGGER, which store.Constraint
--   would confuse with the builtin-admin triggers.
--   History rows (audit, runs, update requests) use ON DELETE SET NULL and keep
--   a copied name, so they survive the user or instance being deleted.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- Instances ------------------------------------------------------------------

CREATE TABLE instances (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE CHECK (name <> ''),
    base_url    TEXT    NOT NULL CHECK (base_url <> ''),
    env_name    TEXT    NOT NULL UNIQUE CHECK (env_name <> '' AND env_name NOT GLOB '*[^A-Z0-9_]*'),
    tls_mode    TEXT    NOT NULL DEFAULT 'verify' CHECK (tls_mode IN ('verify', 'insecure')),
    ca_file     TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    created_at  INTEGER NOT NULL,
    CHECK (ca_file IS NULL OR tls_mode = 'verify')
);

-- UNIQUE (id, mode) is the parent key for instance_group_members, so a member
-- row always carries its group's current mode (kept in step by ON UPDATE CASCADE).
-- The app also checks that a mirrored group's primary is one of its members.
CREATE TABLE instance_groups (
    id                  INTEGER PRIMARY KEY,
    name                TEXT    NOT NULL UNIQUE CHECK (name <> ''),
    mode                TEXT    NOT NULL CHECK (mode IN ('independent', 'mirrored')),
    primary_instance_id INTEGER REFERENCES instances (id),
    created_at          INTEGER NOT NULL,
    UNIQUE (id, mode),
    CHECK ((mode = 'mirrored') = (primary_instance_id IS NOT NULL))
);

CREATE TABLE instance_group_members (
    group_id    INTEGER NOT NULL,
    group_mode  TEXT    NOT NULL,
    instance_id INTEGER NOT NULL REFERENCES instances (id),
    PRIMARY KEY (group_id, instance_id),
    FOREIGN KEY (group_id, group_mode) REFERENCES instance_groups (id, mode)
        ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX instance_group_members_instance ON instance_group_members (instance_id);

-- An instance can be in at most one mirrored group. This also fires when an
-- independent group is switched to mirrored, through the cascaded group_mode.
CREATE UNIQUE INDEX instance_group_members_one_mirrored
    ON instance_group_members (instance_id) WHERE group_mode = 'mirrored';

-- Users, roles and grants ----------------------------------------------------

-- username is lowercased by the app. lower() here is ASCII-only, so this CHECK
-- is a backstop, not the normalisation itself.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE CHECK (username <> '' AND username = lower(username)),
    source        TEXT    NOT NULL CHECK (source IN ('local', 'ldap')),
    ldap_dn       TEXT,
    password_hash TEXT,
    disabled      BOOLEAN NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    CHECK ((source = 'local' AND password_hash IS NOT NULL AND ldap_dn IS NULL)
        OR (source = 'ldap' AND password_hash IS NULL AND ldap_dn IS NOT NULL))
);

CREATE TABLE roles (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (name <> ''),
    description TEXT    NOT NULL DEFAULT '',
    builtin     BOOLEAN NOT NULL DEFAULT 0 CHECK (builtin IN (0, 1)),
    created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX roles_one_builtin ON roles (builtin) WHERE builtin = 1;

-- permission is validated against the catalogue in internal/rbac, not here.
-- Which scopes a permission allows (invariant 6) is also checked there.
CREATE TABLE role_grants (
    id          INTEGER PRIMARY KEY,
    role_id     INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission  TEXT    NOT NULL CHECK (permission <> ''),
    scope_type  TEXT    NOT NULL CHECK (scope_type IN ('all', 'group', 'instance')),
    instance_id INTEGER REFERENCES instances (id),
    group_id    INTEGER REFERENCES instance_groups (id),
    CHECK ((scope_type = 'all'      AND instance_id IS NULL     AND group_id IS NULL)
        OR (scope_type = 'instance' AND instance_id IS NOT NULL AND group_id IS NULL)
        OR (scope_type = 'group'    AND group_id IS NOT NULL    AND instance_id IS NULL))
);

-- SQLite treats NULLs as distinct in UNIQUE constraints, hence the expression index.
CREATE UNIQUE INDEX role_grants_unique
    ON role_grants (role_id, permission, scope_type, ifnull(instance_id, 0), ifnull(group_id, 0));
CREATE INDEX role_grants_instance ON role_grants (instance_id);
CREATE INDEX role_grants_group ON role_grants (group_id);

-- Local users only (checked by the app). LDAP users get roles from role_ldap_groups.
CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles (id),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role ON user_roles (role_id);

CREATE TABLE role_ldap_groups (
    id            INTEGER PRIMARY KEY,
    role_id       INTEGER NOT NULL REFERENCES roles (id),
    group_dn      TEXT    NOT NULL CHECK (group_dn <> ''),
    group_dn_norm TEXT    NOT NULL CHECK (group_dn_norm <> ''),
    created_at    INTEGER NOT NULL,
    UNIQUE (role_id, group_dn_norm)
);

CREATE INDEX role_ldap_groups_dn ON role_ldap_groups (group_dn_norm);

-- Invariant 1 as a database backstop: the builtin admin role and its grants
-- can't be changed or removed, and only scope-'all' grants can be added to it.
-- A later migration that renames a permission has to drop and recreate these.

-- +goose StatementBegin
CREATE TRIGGER roles_builtin_no_update BEFORE UPDATE ON roles
WHEN OLD.builtin = 1
BEGIN
    SELECT RAISE(ABORT, 'the builtin admin role cannot be changed');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER roles_builtin_no_delete BEFORE DELETE ON roles
WHEN OLD.builtin = 1
BEGIN
    SELECT RAISE(ABORT, 'the builtin admin role cannot be deleted');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_insert BEFORE INSERT ON role_grants
WHEN NEW.scope_type <> 'all' AND (SELECT builtin FROM roles WHERE id = NEW.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants are always scope all');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_update BEFORE UPDATE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
  OR (SELECT builtin FROM roles WHERE id = NEW.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be changed');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd

-- Sessions and setup ---------------------------------------------------------

-- id_hash is SHA-256 of the session ID. public_id is 16 random bytes,
-- base64url without padding (22 characters).
CREATE TABLE sessions (
    id_hash          BLOB    PRIMARY KEY CHECK (length(id_hash) = 32),
    public_id        TEXT    NOT NULL UNIQUE CHECK (length(public_id) = 22),
    user_id          INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    roles_checked_at INTEGER NOT NULL,
    ip               TEXT    NOT NULL DEFAULT '',
    user_agent       TEXT    NOT NULL DEFAULT '',
    CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- The role IDs a session holds ("sessions store role IDs"). For LDAP users
-- these come from the group mapping at login and are replaced at each recheck.
CREATE TABLE session_roles (
    session_id_hash BLOB    NOT NULL REFERENCES sessions (id_hash) ON DELETE CASCADE,
    role_id         INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (session_id_hash, role_id)
);

CREATE INDEX session_roles_role ON session_roles (role_id);

CREATE TABLE setup_state (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    completed_at     INTEGER,
    setup_token_hash BLOB,
    token_expires_at INTEGER,
    CHECK ((setup_token_hash IS NULL) = (token_expires_at IS NULL))
);

-- Configuration ----------------------------------------------------------------

CREATE TABLE settings (
    key        TEXT    PRIMARY KEY CHECK (key <> ''),
    value      TEXT    NOT NULL CHECK (json_valid(value)),
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL DEFAULT ''
);

-- The secret is AES-256-GCM (12-byte nonce). Ciphertext, nonce and key ID are
-- all set or all NULL. secret_updated_* back the "last changed on DATE by USER" line.
CREATE TABLE notification_channels (
    id                INTEGER PRIMARY KEY,
    kind              TEXT    NOT NULL CHECK (kind IN ('discord', 'matrix')),
    name              TEXT    NOT NULL UNIQUE CHECK (name <> ''),
    -- Optional. When PIHOLE_RBAC_NOTIFY_<env_name>_SECRET (or _FILE) is set, it overrides the stored secret.
    env_name          TEXT    UNIQUE CHECK (env_name IS NULL OR (env_name <> '' AND env_name NOT GLOB '*[^A-Z0-9_]*')),
    config            TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(config)),
    secret_ciphertext BLOB,
    secret_nonce      BLOB    CHECK (secret_nonce IS NULL OR length(secret_nonce) = 12),
    secret_key_id     TEXT,
    secret_updated_at INTEGER,
    secret_updated_by TEXT,
    enabled           BOOLEAN NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at        INTEGER NOT NULL,
    CHECK ((secret_ciphertext IS NULL) = (secret_nonce IS NULL)
       AND (secret_ciphertext IS NULL) = (secret_key_id IS NULL))
);

CREATE TABLE notification_rules (
    channel_id INTEGER NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    event      TEXT    NOT NULL CHECK (event <> ''),
    PRIMARY KEY (channel_id, event)
);

-- Operations -------------------------------------------------------------------

-- Append-only by convention (the app never updates rows, only prunes by age).
CREATE TABLE audit_log (
    id            INTEGER PRIMARY KEY,
    at            INTEGER NOT NULL,
    user_id       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    username      TEXT    NOT NULL DEFAULT '',
    action        TEXT    NOT NULL CHECK (action <> ''),
    target        TEXT    NOT NULL DEFAULT '',
    instance_id   INTEGER REFERENCES instances (id) ON DELETE SET NULL,
    instance_name TEXT    NOT NULL DEFAULT '',
    result        TEXT    NOT NULL CHECK (result <> ''),
    detail        TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    ip            TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_user ON audit_log (user_id);
CREATE INDEX audit_log_action ON audit_log (action);
CREATE INDEX audit_log_instance ON audit_log (instance_id);

CREATE TABLE client_reset_targets (
    id             INTEGER PRIMARY KEY,
    instance_id    INTEGER REFERENCES instances (id),
    group_id       INTEGER REFERENCES instance_groups (id),
    comment_prefix TEXT    NOT NULL DEFAULT '',
    target_groups  TEXT    NOT NULL DEFAULT '[]'
                   CHECK (json_valid(target_groups) AND json_type(target_groups) = 'array'),
    CHECK ((instance_id IS NULL) <> (group_id IS NULL))
);

CREATE TABLE client_reset_runs (
    id          INTEGER PRIMARY KEY,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER,
    trigger     TEXT    NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    user_id     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    username    TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'partial', 'failed')),
    summary     TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(summary)),
    CHECK ((status = 'running') = (finished_at IS NULL))
);

-- Serialises runs: at most one row can be 'running'.
CREATE UNIQUE INDEX client_reset_runs_one_running ON client_reset_runs (status) WHERE status = 'running';
CREATE INDEX client_reset_runs_started ON client_reset_runs (started_at);

-- The GLOB is a backstop. The app validates target_version against ^v\d+\.\d+\.\d+$.
CREATE TABLE update_requests (
    id                INTEGER PRIMARY KEY,
    requested_at      INTEGER NOT NULL,
    requested_by      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    requested_by_name TEXT    NOT NULL DEFAULT '',
    target_version    TEXT    CHECK (target_version IS NULL OR target_version GLOB 'v[0-9]*.[0-9]*.[0-9]*'),
    status            TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'running', 'done', 'failed', 'rolled_back')),
    log               TEXT    NOT NULL DEFAULT '',
    finished_at       INTEGER
);

-- Seed data ----------------------------------------------------------------------

INSERT INTO setup_state (id) VALUES (1);

-- The builtin admin role exists from the first migration, so invariant 1 holds
-- before setup has run. Each new permission arrives in a migration that grants
-- it here. Milestone 5 adds a test in internal/rbac that this list matches the catalogue.
INSERT INTO roles (id, name, description, builtin, created_at)
VALUES (1, 'admin', 'Built-in administrator: every permission on every instance. Cannot be changed.', 1,
        CAST(strftime('%s', 'now') AS INTEGER) * 1000);

INSERT INTO role_grants (role_id, permission, scope_type)
SELECT 1, value, 'all' FROM json_each('[
    "domains.view", "domains.edit", "clients.view", "clients.edit", "querylog.view",
    "blocking.toggle", "dns.restart", "clientreset.run",
    "drift.view", "drift.reconcile",
    "instances.manage", "settings.manage", "notifications.manage", "users.manage",
    "roles.manage", "sessions.manage", "audit.view", "config.reload", "app.update"
]');

-- +goose Down

DROP TABLE update_requests;
DROP TABLE client_reset_runs;
DROP TABLE client_reset_targets;
DROP TABLE audit_log;
DROP TABLE notification_rules;
DROP TABLE notification_channels;
DROP TABLE settings;
DROP TABLE setup_state;
DROP TABLE session_roles;
DROP TABLE sessions;
DROP TABLE role_ldap_groups;
DROP TABLE user_roles;
DROP TABLE role_grants;
DROP TABLE roles;
DROP TABLE users;
DROP TABLE instance_group_members;
DROP TABLE instance_groups;
DROP TABLE instances;
