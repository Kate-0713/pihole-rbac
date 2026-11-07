-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- client_reset_scheduled: scheduled client reset runs get their own notification event, so a channel can receive
-- manual runs (client_reset) without scheduled ones, or the reverse. Before this, client_reset covered both, so every
-- channel that receives client_reset is subscribed to the new event too and nothing goes quiet on upgrade.
--
-- Avoid semicolons at the end of comment lines: goose splits statements on them.

-- +goose Up

INSERT OR IGNORE INTO notification_rules (channel_id, event)
SELECT channel_id, 'client_reset_scheduled' FROM notification_rules WHERE event = 'client_reset';

-- +goose Down

DELETE FROM notification_rules WHERE event = 'client_reset_scheduled';
