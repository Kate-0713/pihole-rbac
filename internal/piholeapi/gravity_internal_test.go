// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
)

// TestReadGravityOutput: lines are passed on cleaned and without their newline, the last line is the last non-empty
// one, a long line is cut, and a read error that isn't the end of the output is returned.
func TestReadGravityOutput(t *testing.T) {
	long := strings.Repeat("x", maxGravityLine+10)
	tests := []struct {
		name      string
		in        io.Reader
		wantLines []string
		wantLast  string
		wantErr   bool
	}{
		{
			name:      "plain lines",
			in:        strings.NewReader("one\ntwo\n"),
			wantLines: []string{"one", "two"},
			wantLast:  "two",
		},
		{
			name:      "a redrawn line is passed as shown, and blank lines don't count as the last",
			in:        strings.NewReader("  [i] Gravity...\r\x1b[K  Gravity failed  \n\n   \n"),
			wantLines: []string{"  Gravity failed", "", ""},
			wantLast:  "Gravity failed",
		},
		{
			name:      "a last line without a newline",
			in:        strings.NewReader("one\nGravity failed"),
			wantLines: []string{"one", "Gravity failed"},
			wantLast:  "Gravity failed",
		},
		{
			name:      "a long line is cut and the next one is whole",
			in:        iotest.OneByteReader(strings.NewReader(long + "\nnext\n")),
			wantLines: []string{long[:maxGravityLine], "next"},
			wantLast:  "next",
		},
		{
			name:      "a read error",
			in:        io.MultiReader(strings.NewReader("one\ntw"), iotest.ErrReader(io.ErrUnexpectedEOF)),
			wantLines: []string{"one", "tw"},
			wantLast:  "tw",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			last, err := readGravityOutput(tt.in, func(l string) { got = append(got, l) })
			if (err != nil) != tt.wantErr || (tt.wantErr && !errors.Is(err, io.ErrUnexpectedEOF)) {
				t.Errorf("err = %v", err)
			}
			if last != tt.wantLast {
				t.Errorf("last = %q, want %q", last, tt.wantLast)
			}
			if !slices.Equal(got, tt.wantLines) {
				t.Errorf("lines %q, want %q", got, tt.wantLines)
			}
		})
	}
}

func TestCleanGravityLine(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"  [i] Pulling...\r\x1b[K  [✓] Pulling", "  [✓] Pulling"},
		{"done\r", "done"}, // nothing drawn after the carriage return
		{"\x1b[1m\x1b[32mgreen\x1b[0m text", "green text"}, // colour codes
		{"a\x1b]0;title\x07b", "a0;titleb"},                // another escape loses ESC and the next character; BEL is dropped
		{"tab\there", "tab here"},
		{"nul\x00 and del\x7f", "nul and del"},
		{"bad \xff utf8", "bad \uFFFD utf8"},
		{"trailing   ", "trailing"},
		{"\x1b[", ""},
	} {
		if got := CleanGravityLine(tt.in); got != tt.want {
			t.Errorf("CleanGravityLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
