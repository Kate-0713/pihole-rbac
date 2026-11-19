// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metricstest lets a test hand its registry's output to promtool. A test that has filled a registry calls
// Dump, and when PIHOLE_RBAC_METRICS_DUMP_DIR is set the output is written there, one file per test, for
// deploy/prometheus/check.sh to run `promtool check metrics` over. With the variable unset it does nothing.
package metricstest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/metrics"
)

// DumpDirVar names the directory the output goes to.
const DumpDirVar = "PIHOLE_RBAC_METRICS_DUMP_DIR"

// Dump writes r's exposition to <dir>/<test name>.txt when the dump directory is set.
func Dump(t testing.TB, r *metrics.Registry) {
	t.Helper()
	dir := os.Getenv(DumpDirVar)
	if dir == "" || r == nil {
		return
	}
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
