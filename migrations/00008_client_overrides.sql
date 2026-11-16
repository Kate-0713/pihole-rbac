-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Temporary client group changes: one client moved into other Pi-hole groups until ends_at, then put back by the
-- app. No permission changes: clients.edit starts, changes and ends one, and clients.view reads them.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

-- The override: one client on one target (an instance or a mirrored group). status is active until every member has
-- settled, then reverted (it ran its time), ended (someone ended it early) or failed (a member was given up on, or
-- lost its client). finished_at is when the last member settled. ended_by and ended_at are set when a person ended
-- it early.
CREATE TABLE client_group_overrides (
    id          INTEGER PRIMARY KEY,
    instance_id INTEGER REFERENCES instances (id) ON DELETE CASCADE,
    group_id    INTEGER REFERENCES instance_groups (id) ON DELETE CASCADE,
    client      TEXT    NOT NULL CHECK (length(client) BETWEEN 1 AND 255),
    starts_at   INTEGER NOT NULL,
    ends_at     INTEGER NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '' CHECK (length(reason) <= 200),
    status      TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reverted', 'ended', 'failed')),
    created_by  TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    ended_by    TEXT,
    ended_at    INTEGER,
    finished_at INTEGER,
    CHECK ((instance_id IS NULL) <> (group_id IS NULL)),
    CHECK (ends_at > starts_at),
    CHECK ((ended_by IS NULL) = (ended_at IS NULL)),
    CHECK ((status = 'active') = (finished_at IS NULL))
);

CREATE INDEX client_group_overrides_status ON client_group_overrides (status, ends_at);

-- One row per member that took the change, with that member's own groups as Pi-hole group names. client is copied
-- from the override so the unique index below needs no join: a client has at most one active override on an
-- instance, whatever the target. active becomes 0 when the member settles (its revert worked, or the client was
-- deleted, or it was given up on).
CREATE TABLE client_group_override_members (
    id              INTEGER PRIMARY KEY,
    override_id     INTEGER NOT NULL REFERENCES client_group_overrides (id) ON DELETE CASCADE,
    instance_id     INTEGER NOT NULL REFERENCES instances (id) ON DELETE CASCADE,
    client          TEXT    NOT NULL CHECK (length(client) BETWEEN 1 AND 255),
    original_groups TEXT    NOT NULL CHECK (json_valid(original_groups) AND json_type(original_groups) = 'array'),
    override_groups TEXT    NOT NULL CHECK (json_valid(override_groups) AND json_type(override_groups) = 'array'),
    active          INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    revert_status   TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (revert_status IN ('pending', 'ok', 'failed', 'skipped', 'given_up')),
    revert_code     TEXT,
    revert_details  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(revert_details) AND json_type(revert_details) = 'object'),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    reverted_at     INTEGER,
    UNIQUE (override_id, instance_id),
    CHECK (revert_status NOT IN ('ok', 'given_up') OR active = 0),
    CHECK (revert_status <> 'pending' OR active = 1)
);

CREATE UNIQUE INDEX client_group_override_members_active ON client_group_override_members (instance_id, client) WHERE active = 1;
CREATE INDEX client_group_override_members_override ON client_group_override_members (override_id);

-- +goose Down

DROP TABLE client_group_override_members;
DROP TABLE client_group_overrides;
