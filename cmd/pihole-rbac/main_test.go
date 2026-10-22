// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"version", []string{"version"}, false},
		{"help", []string{"help"}, false},
		{"unknown", []string{"frobnicate"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := run(tt.args); (err != nil) != tt.wantErr {
				t.Fatalf("run(%v) err = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}
}

func TestVersionTextReportsFrontend(t *testing.T) {
	got := versionText()
	if !strings.Contains(got, "frontend: embedded") && !strings.Contains(got, "frontend: not built") {
		t.Fatalf("versionText() = %q, missing frontend line", got)
	}
	if !strings.Contains(got, "source: "+buildinfo.Source) {
		t.Fatalf("versionText() = %q, missing source line", got)
	}
}
