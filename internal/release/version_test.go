// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"errors"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want Version
		ok   bool
	}{
		{"v2.1.0", Version{2, 1, 0, ""}, true},
		{"2.1.0", Version{2, 1, 0, ""}, true},
		{"v2.0.0-rc.1", Version{2, 0, 0, "rc.1"}, true},
		{"v2.0.0-rc1", Version{2, 0, 0, "rc1"}, true},
		{"v10.20.30-alpha.beta.3", Version{10, 20, 30, "alpha.beta.3"}, true},
		{"v0.0.0", Version{}, true},
		{"", Version{}, false},
		{"dev", Version{}, false},
		{"v2", Version{}, false},
		{"v2.1", Version{}, false},
		{"V2.1.0", Version{}, false},
		{"vv2.1.0", Version{}, false},
		{"v02.1.0", Version{}, false},
		{"v2.1.0-", Version{}, false},
		{"v2.1.0-rc..1", Version{}, false},
		{"v2.1.0-rc.1-3-gabc1234", Version{}, false}, // git describe between tags
		{"2.1.1-snapshot+abc1234", Version{}, false}, // GoReleaser snapshot
		{"v2.1.0 ", Version{}, false},
		{"v2.1.0\n", Version{}, false},
		{"v2.1.0/../../x", Version{}, false},
		{"v99999999999999999999.0.0", Version{}, false}, // overflows uint64
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseVersion(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil {
				if !errors.Is(err, ErrVersion) {
					t.Errorf("err = %v, want ErrVersion", err)
				}
				return
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseTag(t *testing.T) {
	if _, err := ParseTag("2.1.0"); err == nil {
		t.Error("a tag without the v was accepted")
	}
	v, err := ParseTag("v2.1.0-rc.2")
	if err != nil {
		t.Fatal(err)
	}
	if v.Tag() != "v2.1.0-rc.2" || v.String() != "2.1.0-rc.2" || !v.IsPrerelease() {
		t.Errorf("Tag %q, String %q, IsPrerelease %v", v.Tag(), v.String(), v.IsPrerelease())
	}
}

func TestCompare(t *testing.T) {
	// In order, oldest first: the example from the semantic versioning spec, plus a few.
	ordered := []string{
		"0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
		"1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "1.10.0", "2.0.0-rc.1", "2.0.0-rc.2", "2.0.0-rc.10", "2.0.0", "10.0.0",
	}
	vs := make([]Version, len(ordered))
	for i, s := range ordered {
		v, err := ParseVersion(s)
		if err != nil {
			t.Fatal(err)
		}
		vs[i] = v
	}
	for i := range vs {
		for j := range vs {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := vs[i].Compare(vs[j]); got != want {
				t.Errorf("%s vs %s = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
}

func TestCurrentOf(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"2.0.0-rc.1", true}, // GoReleaser
		{"v2.0.0", true},     // make build on a tag
		{"v2.0.0-dirty", false},
		{"v2.0.0-3-gabc1234-dirty", false},
		{"dev", false},
		{"abc1234", false}, // git describe --always without tags
		{"2.0.1-snapshot+abc1234", false},
	}
	for _, tt := range tests {
		if _, ok := currentOf(tt.in); ok != tt.ok {
			t.Errorf("currentOf(%q) ok = %v, want %v", tt.in, ok, tt.ok)
		}
	}
}
