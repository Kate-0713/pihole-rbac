-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Audit log forwarding: syslog destinations, and for each the last audit_log row it was sent. logging.manage is
-- needed to manage destinations, and only the builtin admin role gets it here, so after upgrading nobody else can
-- until an admin grants it.
--
-- audit_log is rebuilt with AUTOINCREMENT. A cursor is the ID of the last row sent, so an ID must never be used
-- twice: without AUTOINCREMENT, SQLite gives a new row the highest ID in the table plus one, so when the retention
-- pruned every row and the app then wrote audit_prune, that row would take an ID a destination has already passed
-- and never be sent. No table has a foreign key to audit_log, so it can be dropped and renamed inside the migration's
-- transaction. Existing rows keep their IDs.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- Scope all grants on the builtin role are allowed by role_grants_builtin_insert.
INSERT INTO role_grants (role_id, permission, scope_type)
SELECT id, 'logging.manage', 'all' FROM roles WHERE builtin = 1;

CREATE TABLE audit_log_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
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

INSERT INTO audit_log_new (id, at, user_id, username, action, target, instance_id, instance_name, result, detail, ip)
SELECT id, at, user_id, username, action, target, instance_id, instance_name, result, detail, ip FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;

CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_user ON audit_log (user_id);
CREATE INDEX audit_log_action ON audit_log (action);
CREATE INDEX audit_log_instance ON audit_log (instance_id);

-- A syslog destination. transport is tls (the default), tcp or udp. tls_mode and ca_file only mean something for tls,
-- and a CA file only with verify, as for instances. The name is unique ignoring case. There are no secrets.
CREATE TABLE log_destinations (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL COLLATE NOCASE UNIQUE CHECK (name <> ''),
    host       TEXT    NOT NULL CHECK (host <> ''),
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    transport  TEXT    NOT NULL DEFAULT 'tls' CHECK (transport IN ('tls', 'tcp', 'udp')),
    tls_mode   TEXT    NOT NULL DEFAULT 'verify' CHECK (tls_mode IN ('verify', 'insecure')),
    ca_file    TEXT,
    enabled    BOOLEAN NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    created_by TEXT    NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL DEFAULT '',
    CHECK (ca_file IS NULL OR (transport = 'tls' AND tls_mode = 'verify' AND ca_file <> ''))
);

-- The last audit_log.id sent to a destination, kept apart so that a destination's settings aren't rewritten after
-- every batch. A new destination starts at the newest row, so it sends new events only.
CREATE TABLE log_destination_cursors (
    destination_id INTEGER PRIMARY KEY REFERENCES log_destinations (id) ON DELETE CASCADE,
    last_id        INTEGER NOT NULL CHECK (last_id >= 0),
    updated_at     INTEGER NOT NULL
);

-- +goose Down

DROP TABLE log_destination_cursors;
DROP TABLE log_destinations;

DELETE FROM role_grants WHERE permission = 'logging.manage' AND role_id NOT IN (SELECT id FROM roles WHERE builtin = 1);

-- The builtin role's grants are protected by role_grants_builtin_no_delete, so the trigger is dropped around the
-- delete and recreated exactly as 00001 defines it.
DROP TRIGGER role_grants_builtin_no_delete;

DELETE FROM role_grants WHERE permission = 'logging.manage';

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd

-- Back to audit_log as 00001 defines it.
CREATE TABLE audit_log_old (
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

INSERT INTO audit_log_old (id, at, user_id, username, action, target, instance_id, instance_name, result, detail, ip)
SELECT id, at, user_id, username, action, target, instance_id, instance_name, result, detail, ip FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_old RENAME TO audit_log;

CREATE INDEX audit_log_at ON audit_log (at);
CREATE INDEX audit_log_user ON audit_log (user_id);
CREATE INDEX audit_log_action ON audit_log (action);
CREATE INDEX audit_log_instance ON audit_log (instance_id);
