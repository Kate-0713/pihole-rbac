// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"slices"
	"testing"
)

func TestNet(t *testing.T) {
	tests := []struct {
		name                   string
		original, override     []string
		wantAdded, wantRemoved []string
	}{
		{"moved", []string{"Default", "Kids"}, []string{"Default"}, nil, []string{"Kids"}},
		{"added", []string{"Default"}, []string{"Default", "Guests"}, []string{"Guests"}, nil},
		{"swapped", []string{"Default", "Kids"}, []string{"Default", "Open"}, []string{"Open"}, []string{"Kids"}},
		{"nothing", []string{"A", "B"}, []string{"B", "A"}, nil, nil},
		{"empty override", []string{"Default", "Kids"}, nil, nil, []string{"Default", "Kids"}},
		{"from none", nil, []string{"Open"}, []string{"Open"}, nil},
		{"duplicates", []string{"A", "A", "B"}, []string{"C", "C"}, []string{"C"}, []string{"A", "B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := Net(tt.original, tt.override)
			if !slices.Equal(added, tt.wantAdded) || !slices.Equal(removed, tt.wantRemoved) {
				t.Fatalf("Net = %v, %v; want %v, %v", added, removed, tt.wantAdded, tt.wantRemoved)
			}
		})
	}
}

func TestRevert(t *testing.T) {
	tests := []struct {
		name                        string
		current, original, override []string
		want                        []string
	}{
		{"untouched", []string{"Default"}, []string{"Default", "Kids"}, []string{"Default"}, []string{"Default", "Kids"}},
		{"the example in the design: Guests added meanwhile", []string{"Default", "Guests"}, []string{"Default", "Kids"}, []string{"Default"}, []string{"Default", "Guests", "Kids"}},
		{"added group removed", []string{"Default", "Open"}, []string{"Default"}, []string{"Default", "Open"}, []string{"Default"}},
		{"swap", []string{"Default", "Open"}, []string{"Default", "Kids"}, []string{"Default", "Open"}, []string{"Default", "Kids"}},
		{"someone else already put it back", []string{"Default", "Kids"}, []string{"Default", "Kids"}, []string{"Default"}, []string{"Default", "Kids"}},
		{"someone else already removed the added group", []string{"Default"}, []string{"Default"}, []string{"Default", "Open"}, []string{"Default"}},
		{"someone else removed an untouched group: kept removed", []string{"Open"}, []string{"Default", "Kids"}, []string{"Open"}, []string{"Default", "Kids"}},
		{"empty override", nil, []string{"Default", "Kids"}, nil, []string{"Default", "Kids"}},
		{"override changed nothing", []string{"A", "C"}, []string{"A", "B"}, []string{"A", "B"}, []string{"A", "C"}},
		{"current has duplicates", []string{"A", "A"}, []string{"A"}, []string{"A"}, []string{"A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Revert(tt.current, tt.original, tt.override); !slices.Equal(got, tt.want) {
				t.Fatalf("Revert(%v, %v, %v) = %v, want %v", tt.current, tt.original, tt.override, got, tt.want)
			}
		})
	}
}

func TestPresent(t *testing.T) {
	exists := func(n string) bool { return n != "Gone" }
	kept, missing := Present([]string{"Default", "Gone", "Kids"}, exists)
	if !slices.Equal(kept, []string{"Default", "Kids"}) || !slices.Equal(missing, []string{"Gone"}) {
		t.Fatalf("Present = %v, %v", kept, missing)
	}
	if k, m := Present(nil, exists); k != nil || m != nil {
		t.Fatalf("Present(nil) = %v, %v", k, m)
	}
}

func TestSame(t *testing.T) {
	for _, tt := range []struct {
		a, b []string
		want bool
	}{
		{[]string{"A", "B"}, []string{"B", "A"}, true},
		{[]string{"A", "A"}, []string{"A"}, true},
		{nil, nil, true},
		{[]string{"A"}, nil, false},
		{[]string{"A"}, []string{"B"}, false},
	} {
		if got := Same(tt.a, tt.b); got != tt.want {
			t.Errorf("Same(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
