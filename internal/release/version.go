// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package release knows where releases come from and how to check them: the fixed GitHub repository, the release
// signing key (built in, never configurable), versions and their order, and verified downloads of a release's
// checksums and archives. The update check and the updater both use it, and neither takes a source or a key from
// anywhere else.
package release

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
)

// Version is a release version: MAJOR.MINOR.PATCH with an optional prerelease such as "rc.1". Build metadata
// ("+...") isn't accepted, so snapshot and git-describe builds don't parse and count as development builds.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 string // without the hyphen; empty for a release
}

var versionRE = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*))?$`)

// ErrVersion is returned for a string that isn't a version.
var ErrVersion = errors.New("not a version (want vX.Y.Z or vX.Y.Z-prerelease, e.g. v2.1.0 or v2.1.0-rc.1)")

// ParseVersion parses a version with or without the leading "v" (GoReleaser sets the build's version without it).
func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(s)
	if m == nil || len(s) > 64 {
		return Version{}, fmt.Errorf("%q: %w", s, ErrVersion)
	}
	var v Version
	var err error
	if v.Major, err = strconv.ParseUint(m[1], 10, 64); err != nil {
		return Version{}, fmt.Errorf("%q: %w", s, ErrVersion)
	}
	if v.Minor, err = strconv.ParseUint(m[2], 10, 64); err != nil {
		return Version{}, fmt.Errorf("%q: %w", s, ErrVersion)
	}
	if v.Patch, err = strconv.ParseUint(m[3], 10, 64); err != nil {
		return Version{}, fmt.Errorf("%q: %w", s, ErrVersion)
	}
	v.Pre = m[4]
	return v, nil
}

// ParseTag parses a release tag, which must start with "v". Requests from the API and the command line use this.
func ParseTag(s string) (Version, error) {
	if !strings.HasPrefix(s, "v") {
		return Version{}, fmt.Errorf("%q: %w", s, ErrVersion)
	}
	return ParseVersion(s)
}

// String is the version without the "v", as in archive names: "2.1.0-rc.1".
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Tag is the Git tag: "v2.1.0-rc.1".
func (v Version) Tag() string { return "v" + v.String() }

// IsPrerelease reports whether the version has a prerelease part.
func (v Version) IsPrerelease() bool { return v.Pre != "" }

// Compare orders versions by semantic versioning precedence: -1 if v is older than o, 0 if equal, +1 if newer. A
// prerelease is older than its release (2.1.0-rc.1 < 2.1.0); prerelease identifiers compare numerically when both
// are numbers, otherwise as text, with numbers first, and a shorter list first when one is a prefix of the other.
func (v Version) Compare(o Version) int {
	if c := cmp.Compare(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	a, b := strings.Split(v.Pre, "."), strings.Split(o.Pre, ".")
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

func compareIdent(a, b string) int {
	an, aErr := strconv.ParseUint(a, 10, 64)
	bn, bErr := strconv.ParseUint(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		return cmp.Compare(an, bn)
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// Current is the running build's version. ok is false for a development build ("dev", a snapshot, or a git-describe
// version between tags or of a changed tree), which can't be compared with releases.
func Current() (v Version, ok bool) {
	return currentOf(buildinfo.Version)
}

func currentOf(s string) (Version, bool) {
	// git describe --dirty on a tag gives "v2.1.0-dirty", which would otherwise read as a prerelease.
	if strings.HasSuffix(s, "-dirty") {
		return Version{}, false
	}
	v, err := ParseVersion(s)
	return v, err == nil
}
