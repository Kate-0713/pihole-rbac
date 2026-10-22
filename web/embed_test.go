// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"io/fs"
	"testing"
)

// Dist must work whether or not the frontend has been built, and must report
// which case it's in correctly.
func TestDist(t *testing.T) {
	dist, built := Dist()
	_, err := fs.Stat(dist, "index.html")
	if built != (err == nil) {
		t.Fatalf("built=%v but stat(index.html) err=%v", built, err)
	}
}
