// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ConstraintKind says which kind of database constraint a write broke. The API layer maps these to error codes:
// ForeignKey to "conflict" (still referenced), Trigger to "invariant_violated", Unique to "conflict".
type ConstraintKind int

const (
	NotConstraint ConstraintKind = iota
	ForeignKey
	Unique
	Check
	NotNull
	PrimaryKey
	Trigger // RAISE(ABORT) from one of the builtin-admin triggers
	OtherConstraint
)

func (k ConstraintKind) String() string {
	return [...]string{"none", "foreign key", "unique", "check", "not null", "primary key", "trigger", "other"}[k]
}

// Constraint reports which constraint err broke, or NotConstraint if it isn't a constraint error.
func Constraint(err error) ConstraintKind {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return NotConstraint
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
		return ForeignKey
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
		return Unique
	case sqlite3.SQLITE_CONSTRAINT_CHECK:
		return Check
	case sqlite3.SQLITE_CONSTRAINT_NOTNULL:
		return NotNull
	case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return PrimaryKey
	case sqlite3.SQLITE_CONSTRAINT_TRIGGER:
		return Trigger
	}
	if se.Code()&0xff == sqlite3.SQLITE_CONSTRAINT {
		return OtherConstraint
	}
	return NotConstraint
}

// Millis converts a time to the INTEGER Unix milliseconds stored in the database.
func Millis(t time.Time) int64 { return t.UnixMilli() }

// FromMillis converts a stored timestamp back to a UTC time.
func FromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
