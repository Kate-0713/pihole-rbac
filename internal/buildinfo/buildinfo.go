// Package buildinfo holds the version, commit and build date, set at build
// time with -ldflags "-X pihole-rbac/internal/buildinfo.Version=..." (see the
// Makefile, build.ps1 and .goreleaser.yaml).
package buildinfo

import "fmt"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// String is the one-line form printed by `pihole-rbac version`.
func String() string {
	return fmt.Sprintf("pihole-rbac %s (commit %s, built %s)", Version, Commit, Date)
}
