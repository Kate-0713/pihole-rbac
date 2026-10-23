-- SPDX-FileCopyrightText: 2026 Kate O'Grady
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- name: GetSetupState :one
SELECT * FROM setup_state WHERE id = 1;

-- name: SetSetupToken :execrows
UPDATE setup_state SET setup_token_hash = ?, token_expires_at = ?
WHERE id = 1 AND completed_at IS NULL;

-- name: CompleteSetup :execrows
UPDATE setup_state SET completed_at = ?, setup_token_hash = NULL, token_expires_at = NULL
WHERE id = 1 AND completed_at IS NULL;
