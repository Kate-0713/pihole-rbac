-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Schedules: blocking turned off, or a Pi-hole group turned on or off, for a window that repeats weekly or happens
-- once. schedules.manage reads and changes a target's schedules. Only the builtin admin role gets it, so after
-- upgrading nobody else can until an admin grants it.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- A weekly window starts on each day in days (Monday = 1 ... Sunday = 64) at start_min (minutes after midnight in
-- time_zone) and ends end_days later at end_min. A one-off window runs from starts_at to ends_at (Unix
-- milliseconds). Edges at or before active_from (when the schedule was saved or switched on) are never applied, so a
-- schedule acts from its next edge. last_edge_at and last_edge are the latest edge applied, and last_results each
-- instance's result for it, keyed by instance ID.
CREATE TABLE schedules (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    instance_id  INTEGER REFERENCES instances (id) ON DELETE CASCADE,
    group_id     INTEGER REFERENCES instance_groups (id) ON DELETE CASCADE,
    kind         TEXT    NOT NULL CHECK (kind IN ('blocking_off', 'group_enabled', 'group_disabled')),
    pihole_group TEXT    CHECK (pihole_group <> ''),
    repeat       TEXT    NOT NULL CHECK (repeat IN ('weekly', 'once')),
    days         INTEGER CHECK (days BETWEEN 1 AND 127),
    start_min    INTEGER CHECK (start_min BETWEEN 0 AND 1439),
    end_min      INTEGER CHECK (end_min BETWEEN 0 AND 1439),
    end_days     INTEGER CHECK (end_days BETWEEN 0 AND 7),
    time_zone    TEXT    CHECK (time_zone <> ''),
    starts_at    INTEGER,
    ends_at      INTEGER,
    active_from  INTEGER NOT NULL,
    last_edge_at INTEGER,
    last_edge    TEXT    CHECK (last_edge IN ('start', 'end')),
    last_results TEXT    NOT NULL DEFAULT '{}'
                 CHECK (json_valid(last_results) AND json_type(last_results) = 'object'),
    finished_at  INTEGER,
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at   INTEGER NOT NULL,
    created_by   TEXT    NOT NULL,
    updated_at   INTEGER NOT NULL,
    updated_by   TEXT    NOT NULL,
    CHECK ((instance_id IS NULL) <> (group_id IS NULL)),
    CHECK ((pihole_group IS NULL) = (kind = 'blocking_off')),
    CHECK ((repeat = 'weekly') = (days IS NOT NULL AND start_min IS NOT NULL AND end_min IS NOT NULL
                                  AND end_days IS NOT NULL AND time_zone IS NOT NULL)),
    CHECK (repeat = 'weekly' OR (days IS NULL AND start_min IS NULL AND end_min IS NULL
                                 AND end_days IS NULL AND time_zone IS NULL)),
    CHECK ((repeat = 'once') = (starts_at IS NOT NULL AND ends_at IS NOT NULL)),
    CHECK (repeat = 'once' OR (starts_at IS NULL AND ends_at IS NULL AND finished_at IS NULL)),
    CHECK (ends_at > starts_at),
    CHECK ((last_edge_at IS NULL) = (last_edge IS NULL))
);

-- Names are unique per target, ignoring case. UNIQUE treats NULLs as distinct, so each kind of target gets its own
-- partial index.
CREATE UNIQUE INDEX schedules_instance_name ON schedules (instance_id, name COLLATE NOCASE) WHERE instance_id IS NOT NULL;
CREATE UNIQUE INDEX schedules_group_name ON schedules (group_id, name COLLATE NOCASE) WHERE group_id IS NOT NULL;
CREATE INDEX schedules_running ON schedules (enabled, finished_at);

-- A scope all grant on the builtin role is allowed by role_grants_builtin_insert.
INSERT INTO role_grants (role_id, permission, scope_type)
SELECT id, 'schedules.manage', 'all' FROM roles WHERE builtin = 1;

-- +goose Down

DROP TABLE schedules;

DELETE FROM role_grants
WHERE permission = 'schedules.manage' AND role_id NOT IN (SELECT id FROM roles WHERE builtin = 1);

-- The builtin role's grant is protected by role_grants_builtin_no_delete, so the trigger is dropped around the delete
-- and recreated exactly as 00001 defines it.
DROP TRIGGER role_grants_builtin_no_delete;

DELETE FROM role_grants WHERE permission = 'schedules.manage';

-- +goose StatementBegin
CREATE TRIGGER role_grants_builtin_no_delete BEFORE DELETE ON role_grants
WHEN (SELECT builtin FROM roles WHERE id = OLD.role_id) = 1
BEGIN
    SELECT RAISE(ABORT, 'builtin admin grants cannot be removed');
END;
-- +goose StatementEnd
