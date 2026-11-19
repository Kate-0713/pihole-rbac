// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// DBStore is the Store over the app's database. Rows are read from the read pool, which sees a row as soon as the
// transaction that wrote it commits; the cursor is written through the writer.
type DBStore struct{ S *store.Store }

// NextRows implements Store.
func (d DBStore) NextRows(ctx context.Context, after int64, limit int) ([]db.AuditLog, error) {
	return d.S.Read().ListAuditAfter(ctx, db.ListAuditAfterParams{ID: after, Limit: int64(limit)})
}

// Cursor implements Store.
func (d DBStore) Cursor(ctx context.Context, destination int64) (int64, error) {
	c, err := d.S.Read().GetLogCursor(ctx, destination)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNoCursor
	}
	return c.LastID, err
}

// SetCursor implements Store.
func (d DBStore) SetCursor(ctx context.Context, destination, lastID int64, at time.Time) error {
	return d.S.WithTx(ctx, func(q *db.Queries) error {
		return q.SetLogCursor(ctx, db.SetLogCursorParams{DestinationID: destination, LastID: lastID, UpdatedAt: store.Millis(at)})
	})
}
