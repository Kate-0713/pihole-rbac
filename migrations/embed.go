// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package migrations embeds the goose SQL migrations, which internal/store applies on startup.
// sqlc reads the same files as its schema.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
