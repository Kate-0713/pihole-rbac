// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in   string
		want Target
		ok   bool
	}{
		{"i-1", InstanceTarget(1), true},
		{"g-42", GroupTarget(42), true},
		{"i-9223372036854775807", InstanceTarget(9223372036854775807), true},
		{"", Target{}, false},
		{"i", Target{}, false},
		{"i-", Target{}, false},
		{"i-0", Target{}, false},
		{"i-01", Target{}, false},
		{"i-+1", Target{}, false},
		{"i--1", Target{}, false},
		{"i-1a", Target{}, false},
		{"i-1 ", Target{}, false},
		{"I-1", Target{}, false},
		{"x-1", Target{}, false},
		{"i_1", Target{}, false},
		{"i-99999999999999999999", Target{}, false},
	}
	for _, tt := range tests {
		got, err := ParseTarget(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("ParseTarget(%q) = %v, %v; want %v, ok=%v", tt.in, got, err, tt.want, tt.ok)
		}
		if tt.ok && got.String() != tt.in {
			t.Errorf("ParseTarget(%q).String() = %q", tt.in, got.String())
		}
	}
}
