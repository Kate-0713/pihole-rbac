// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// StoreUsers is the LocalUserStore backed by the users table.
type StoreUsers struct {
	St *store.Store
}

func (u StoreUsers) LocalUserByName(ctx context.Context, username string) (LocalUser, error) {
	row, err := u.St.Read().GetUserByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return LocalUser{}, ErrUserNotFound
	}
	if err != nil {
		return LocalUser{}, err
	}
	// An LDAP user's row has no password hash; to the local method it doesn't exist.
	if Method(row.Source) != MethodLocal || !row.PasswordHash.Valid {
		return LocalUser{}, ErrUserNotFound
	}
	return LocalUser{ID: row.ID, Username: row.Username, PasswordHash: []byte(row.PasswordHash.String), Disabled: row.Disabled}, nil
}
