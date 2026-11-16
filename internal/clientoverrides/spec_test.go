// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func field(t *testing.T, err error) string {
	t.Helper()
	var re *rbac.Error
	if !errors.As(err, &re) || re.Code != rbac.CodeValidation {
		t.Fatalf("error = %v, want a validation refusal", err)
	}
	f, _ := re.Details["field"].(string)
	return f
}

func TestCheckClient(t *testing.T) {
	long := strings.Repeat("a", MaxClientBytes+1)
	for client, ok := range map[string]bool{
		"10.0.1.5": true, "aa:bb:cc:dd:ee:ff": true, "192.168.0.0/24": true, "sam-tablet": true,
		"": false, long: false, "a\nb": false, "a\x00": false, "\xff": false,
	} {
		err := CheckClient(client)
		if (err == nil) != ok {
			t.Errorf("CheckClient(%q) = %v, want ok %v", client, err, ok)
		} else if err != nil && field(t, err) != "client" {
			t.Errorf("CheckClient(%q) names the wrong field", client)
		}
	}
}

func TestCheckGroups(t *testing.T) {
	many := make([]string, MaxGroups+1)
	for i := range many {
		many[i] = strings.Repeat("g", i+1)
	}
	tests := []struct {
		name   string
		groups []string
		ok     bool
	}{
		{"one", []string{"Default"}, true},
		{"empty", nil, true},
		{"two", []string{"Default", "Kids"}, true},
		{"too many", many, false},
		{"exactly the most", many[:MaxGroups], true},
		{"empty name", []string{""}, false},
		{"padded", []string{" Kids"}, false},
		{"newline", []string{"Kids\n"}, false},
		{"twice", []string{"Kids", "Kids"}, false},
		{"same ignoring case is two groups", []string{"Kids", "kids"}, true},
		{"too long", []string{strings.Repeat("é", MaxGroupRunes+1)}, false},
		{"long enough in runes", []string{strings.Repeat("é", MaxGroupRunes)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckGroups(tt.groups)
			if (err == nil) != tt.ok {
				t.Fatalf("CheckGroups = %v, want ok %v", err, tt.ok)
			}
			if err != nil && field(t, err) != "groups" {
				t.Fatalf("wrong field")
			}
		})
	}
}

func TestCheckReason(t *testing.T) {
	tests := []struct {
		name, in string
		required bool
		want     string
		bad      bool
	}{
		{"given", "  Homework  ", true, "Homework", false},
		{"missing and required", "", true, "", true},
		{"blank and required", "   ", true, "", true},
		{"missing and optional", "", false, "", false},
		{"too long", strings.Repeat("x", MaxReasonRunes+1), false, "", true},
		{"longest", strings.Repeat("x", MaxReasonRunes), true, strings.Repeat("x", MaxReasonRunes), false},
		{"control", "a\tb", false, "", true},
		{"newline", "a\nb", true, "", true},
		{"too long in runes, not bytes", strings.Repeat("é", MaxReasonRunes), true, strings.Repeat("é", MaxReasonRunes), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckReason(tt.in, tt.required)
			if tt.bad {
				if err == nil || field(t, err) != "reason" {
					t.Fatalf("err = %v, want a refusal naming reason", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("CheckReason = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestStartEnd(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	l := Limits{Max: 2 * time.Hour}
	i := func(n int) *int { return &n }
	at := func(d time.Duration) *time.Time { x := now.Add(d); return &x }
	tests := []struct {
		name  string
		dur   *int
		end   *time.Time
		want  time.Time
		field string
		max   bool
	}{
		{"duration", i(60), nil, now.Add(time.Hour), "", false},
		{"shortest duration", i(5), nil, now.Add(5 * time.Minute), "", false},
		{"longest duration", i(120), nil, now.Add(2 * time.Hour), "", false},
		{"too short", i(4), nil, time.Time{}, "duration_minutes", false},
		{"over the maximum", i(121), nil, time.Time{}, "duration_minutes", true},
		{"end time", nil, at(90 * time.Minute), now.Add(90 * time.Minute), "", false},
		{"end too soon", nil, at(4 * time.Minute), time.Time{}, "ends_at", false},
		{"end in the past", nil, at(-time.Hour), time.Time{}, "ends_at", false},
		{"end over the maximum", nil, at(121 * time.Minute), time.Time{}, "ends_at", true},
		{"both", i(60), at(time.Hour), time.Time{}, "duration_minutes", false},
		{"neither", nil, nil, time.Time{}, "duration_minutes", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StartEnd(now, tt.dur, tt.end, l)
			if tt.field != "" {
				if f := field(t, err); f != tt.field {
					t.Fatalf("field = %q, want %q", f, tt.field)
				}
				if m, has := err.(*rbac.Error).Details["max_minutes"]; has != tt.max || (has && m != 120) {
					t.Fatalf("max_minutes = %v (present %v), want present %v", m, has, tt.max)
				}
				return
			}
			if err != nil || !got.Equal(tt.want) {
				t.Fatalf("StartEnd = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestCheckExtend(t *testing.T) {
	start := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	now := start.Add(time.Hour)
	l := Limits{Max: 3 * time.Hour}
	tests := []struct {
		name  string
		end   time.Time
		field string
	}{
		{"later within the maximum", start.Add(2 * time.Hour), ""},
		{"exactly the maximum from the start", start.Add(3 * time.Hour), ""},
		{"a minute over the maximum from the start", start.Add(3*time.Hour + time.Minute), "ends_at"},
		{"measured from the start, not from now", now.Add(3 * time.Hour), "ends_at"},
		{"in the past", start.Add(30 * time.Minute), "ends_at"},
		{"now", now, "ends_at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckExtend(now, start, tt.end, l)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if field(t, err) != tt.field {
				t.Fatalf("wrong field: %v", err)
			}
		})
	}
	// An override already at the maximum can't be extended at all.
	if err := CheckExtend(now, start, start.Add(3*time.Hour+time.Second), l); err == nil {
		t.Fatal("extending past the maximum from the start was allowed")
	}
}

func TestCheckMax(t *testing.T) {
	for m, want := range map[int]bool{4: false, 5: true, DefaultMinutes: true, MaxMinutes: true, MaxMinutes + 1: false, 0: false} {
		if CheckMax(m) != want {
			t.Errorf("CheckMax(%d) = %v, want %v", m, !want, want)
		}
	}
}
