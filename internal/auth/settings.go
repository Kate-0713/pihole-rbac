// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// SettingsKey is the settings row holding the login settings.
const SettingsKey = "auth"

// Settings are the login settings stored in the database.
type Settings struct {
	// Methods are the enabled login methods, tried in this order.
	Methods []Method `json:"methods"`
}

// DefaultSettings applies until an admin saves login settings: local accounts only.
func DefaultSettings() Settings {
	return Settings{Methods: []Method{MethodLocal}}
}

// LoadSettings reads the login settings, or the defaults if none have been saved. A saved value that doesn't
// validate is an error rather than a silent fallback, so a bad edit can't quietly change who can log in.
func LoadSettings(ctx context.Context, q *db.Queries) (Settings, error) {
	row, err := q.GetSetting(ctx, SettingsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal([]byte(row.Value), &s); err != nil {
		return Settings{}, fmt.Errorf("settings %q: %w", SettingsKey, err)
	}
	if err := ValidateMethods(s.Methods); err != nil {
		return Settings{}, fmt.Errorf("settings %q: %w", SettingsKey, err)
	}
	return s, nil
}
