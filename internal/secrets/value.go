// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
)

const redacted = "[redacted]"

// Value holds a secret. fmt (every verb), slog and encoding/json (and anything else using encoding.TextMarshaler)
// all see "[redacted]", so a secret can't reach a log line or an API response by accident. Reveal returns the real
// value and is the only way to get it.
type Value struct {
	b []byte
}

// NewValue copies b into a Value.
func NewValue(b []byte) Value {
	return Value{b: append([]byte(nil), b...)}
}

// IsZero reports whether the value is empty (not set).
func (v Value) IsZero() bool { return len(v.b) == 0 }

// Len returns the secret's length in bytes.
func (v Value) Len() int { return len(v.b) }

// Reveal returns the secret as a string.
func (v Value) Reveal() string { return string(v.b) }

// RevealBytes returns a copy of the secret.
func (v Value) RevealBytes() []byte { return append([]byte(nil), v.b...) }

// Equal compares two values in constant time.
func (v Value) Equal(o Value) bool { return subtle.ConstantTimeCompare(v.b, o.b) == 1 }

func (v Value) String() string   { return redacted }
func (v Value) GoString() string { return "secrets.Value{" + redacted + "}" }

// Format covers verbs that would otherwise bypass String, such as %d or %x applied to the struct.
func (v Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

func (v Value) LogValue() slog.Value { return slog.StringValue(redacted) }

func (v Value) MarshalText() ([]byte, error) { return []byte(redacted), nil }
