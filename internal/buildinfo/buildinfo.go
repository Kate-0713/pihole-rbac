// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package buildinfo holds the version, commit and build date, set at build time with -ldflags "-X github.com/Kate-0713/pihole-rbac/internal/buildinfo.Version=..." (see the Makefile, build.ps1 and .goreleaser.yaml).
package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Source is where users can get the source code of this build, as AGPL-3.0 section 13 requires for software used over a network. If you distribute a modified version, point this at your modified source, e.g. with -ldflags "-X github.com/Kate-0713/pihole-rbac/internal/buildinfo.Source=https://...".
var Source = "https://github.com/Kate-0713/pihole-rbac"

// License is the SPDX identifier of the project's licence.
const License = "AGPL-3.0-or-later"

// String is the one-line form printed by `pihole-rbac version`.
func String() string {
	return fmt.Sprintf("pihole-rbac %s (commit %s, built %s)", Version, Commit, Date)
}
