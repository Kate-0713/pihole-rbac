// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

func TestSpecCheck(t *testing.T) {
	utc := zone(t, "UTC")
	now := at(t, utc, "2027-03-01 12:00")
	day := DefaultGroupWindowMinutes * time.Minute
	limits := Limits{MaxGroupWindow: day}
	blocking := func(w Window) Spec { return Spec{Name: "Lab mornings", Kind: KindBlockingOff, Window: w} }
	group := func(w Window) Spec {
		return Spec{Name: "Bedtime", Kind: KindGroupEnabled, PiholeGroup: "bedtime", Window: w}
	}
	once := func(start, end string) Window {
		return Window{Repeat: RepeatOnce, StartsAt: at(t, utc, start), EndsAt: at(t, utc, end)}
	}
	lab := weekly(utc, weekdays, "08:00", "08:30", 0)
	for _, tc := range []struct {
		name   string
		spec   Spec
		limits Limits
		field  string // "" when it is accepted
	}{
		{"a weekday blocking window", blocking(lab), limits, ""},
		{"a group window past midnight", group(weekly(utc, AllDays, "21:00", "07:00", 1)), limits, ""},
		{"a group window disabling a group", Spec{Name: "x", Kind: KindGroupDisabled, PiholeGroup: "strict", Window: lab}, limits, ""},
		{"a whole week, with a long enough limit", group(weekly(utc, Monday, "00:00", "00:00", 7)), Limits{MaxGroupWindow: 365 * day}, ""},
		{"a one-off", blocking(once("2027-03-02 08:00", "2027-03-02 09:00")), limits, ""},
		{"a 24-hour blocking window", blocking(weekly(utc, Monday, "08:00", "08:00", 1)), limits, ""},

		{"no name", Spec{Kind: KindBlockingOff, Window: lab}, limits, "name"},
		{"a name too long", Spec{Name: string(make([]byte, 101)), Kind: KindBlockingOff, Window: lab}, limits, "name"},
		{"a control character", Spec{Name: "a\nb", Kind: KindBlockingOff, Window: lab}, limits, "name"},
		{"a trailing space", Spec{Name: "lab ", Kind: KindBlockingOff, Window: lab}, limits, "name"},
		{"an unknown kind", Spec{Name: "x", Kind: "blocking_on", Window: lab}, limits, "kind"},
		{"a group window without a group", Spec{Name: "x", Kind: KindGroupEnabled, Window: lab}, limits, "pihole_group"},
		{"a blocking window with a group", Spec{Name: "x", Kind: KindBlockingOff, PiholeGroup: "kids", Window: lab}, limits, "pihole_group"},
		{"no repeat", blocking(Window{}), limits, "repeat"},
		{"no days", blocking(weekly(utc, 0, "08:00", "08:30", 0)), limits, "days"},
		{"a day that isn't one", blocking(weekly(utc, 128|Monday, "08:00", "08:30", 0)), limits, "days"},
		{"a start out of range", blocking(Window{Repeat: RepeatWeekly, Days: Monday, Start: 1440, End: 10, Location: utc}), limits, "start"},
		{"an end out of range", blocking(Window{Repeat: RepeatWeekly, Days: Monday, Start: 10, End: -1, Location: utc}), limits, "end"},
		{"end_days over 7", group(weekly(utc, Monday, "08:00", "08:30", 8)), limits, "end_days"},
		{"no time zone", blocking(weekly(nil, Monday, "08:00", "08:30", 0)), limits, "time_zone"},
		{"ending as it starts", blocking(weekly(utc, Monday, "08:00", "08:00", 0)), limits, "end"},
		{"past midnight without end_days", group(weekly(utc, Monday, "21:00", "07:00", 0)), limits, "end"},
		{"overlapping itself", group(weekly(utc, Monday|Tuesday, "08:00", "20:00", 1)), Limits{MaxGroupWindow: 7 * day}, "end_days"},
		{"a blocking window over 24 hours", blocking(weekly(utc, Monday, "08:00", "09:00", 1)), limits, "end_days"},
		{"a group window over the admin's limit", group(weekly(utc, Monday, "08:00", "10:00", 0)), Limits{MaxGroupWindow: time.Hour}, "end_days"},
		{"a one-off group window over the limit", group(once("2027-03-02 08:00", "2027-03-03 09:00")), limits, "ends_at"},
		{"a one-off blocking window over 24 hours", blocking(once("2027-03-02 08:00", "2027-03-03 08:01")), Limits{MaxGroupWindow: 7 * day}, "ends_at"},
		{"a one-off in the past", blocking(once("2027-03-01 11:00", "2027-03-01 13:00")), limits, "starts_at"},
		{"a one-off starting now", blocking(once("2027-03-01 12:00", "2027-03-01 13:00")), limits, "starts_at"},
		{"a one-off ending as it starts", blocking(once("2027-03-02 08:00", "2027-03-02 08:00")), limits, "ends_at"},
		{"a one-off without a start", blocking(Window{Repeat: RepeatOnce}), limits, "starts_at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Check(now, tc.limits)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			re, ok := err.(*rbac.Error)
			if !ok || re.Code != rbac.CodeValidation {
				t.Fatalf("got %v, want a validation error on %s", err, tc.field)
			}
			if re.Details["field"] != tc.field {
				t.Errorf("refused on %v (%s), want %s", re.Details["field"], re.Message, tc.field)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	utc := zone(t, "UTC")
	err := Spec{Name: "x", Kind: KindGroupEnabled, PiholeGroup: "g", Window: weekly(utc, Monday, "08:00", "10:00", 0)}.
		Check(at(t, utc, "2027-03-01 00:00"), Limits{MaxGroupWindow: 90 * time.Minute})
	re, _ := err.(*rbac.Error)
	if re == nil || re.Details["max_minutes"] != 90 || re.Message != "The window can be at most 1 hour 30 minutes long." {
		t.Errorf("got %v", err)
	}

	bedtime := Spec{Name: "Bedtime", Kind: KindGroupEnabled, PiholeGroup: "g", Window: weekly(utc, Monday, "21:00", "07:00", 1)}
	if bedtime.OverLimit(Limits{MaxGroupWindow: 24 * time.Hour}) {
		t.Error("a 10-hour window is over a 24-hour limit")
	}
	if !bedtime.OverLimit(Limits{MaxGroupWindow: 8 * time.Hour}) {
		t.Error("a 10-hour window isn't over an 8-hour limit")
	}
	// With no limit set, the default applies; a weekly window is never over 7 days, whatever the setting.
	if got := (Limits{}).MaxLength(KindGroupEnabled, RepeatOnce); got != 24*time.Hour {
		t.Errorf("the default group window limit is %s", got)
	}
	if got := (Limits{MaxGroupWindow: 30 * 24 * time.Hour}).MaxLength(KindGroupDisabled, RepeatWeekly); got != MaxWeekly {
		t.Errorf("a weekly group window can be %s", got)
	}
	if got := (Limits{MaxGroupWindow: 30 * 24 * time.Hour}).MaxLength(KindBlockingOff, RepeatOnce); got != MaxBlocking {
		t.Errorf("a blocking window can be %s", got)
	}
}

func TestDescribeLength(t *testing.T) {
	for d, want := range map[time.Duration]string{
		24 * time.Hour: "24 hours", 7 * 24 * time.Hour: "7 days", 36 * time.Hour: "1 day 12 hours",
		5 * time.Minute: "5 minutes", 61 * time.Minute: "1 hour 1 minute",
	} {
		if got := describeLength(d); got != want {
			t.Errorf("describeLength(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestLoadZone(t *testing.T) {
	for _, name := range []string{"", "Local", "Nowhere/City", "../../etc/passwd"} {
		if _, err := LoadZone(name); err == nil {
			t.Errorf("%q loaded", name)
		}
	}
	if _, err := LoadZone("Europe/London"); err != nil {
		t.Error(err)
	}
}
