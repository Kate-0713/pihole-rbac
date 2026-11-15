// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"testing"
	"time"
)

func TestGroupEdge(t *testing.T) {
	utc := zone(t, "UTC")
	iv := Interval{at(t, utc, "2027-03-01 21:00"), at(t, utc, "2027-03-02 07:00")}
	open := func(id int64, name string, k Kind, group string) Open {
		return Open{Reach{ID: id, Name: name, Kind: k, Group: group}, iv}
	}
	bedtime := Reach{ID: 1, Name: "Bedtime", Kind: KindGroupEnabled, Group: "bedtime"}
	strictOff := Reach{ID: 2, Name: "Weekend", Kind: KindGroupDisabled, Group: "strict"}
	for _, tc := range []struct {
		name  string
		self  Reach
		start bool
		open  []Open
		want  GroupAction
	}{
		{"an enable window's start", bedtime, true, []Open{open(1, "Bedtime", KindGroupEnabled, "bedtime")}, GroupAction{Send: true, Enabled: true}},
		{"an enable window's end", bedtime, false, nil, GroupAction{Send: true, Enabled: false}},
		{"a disable window's start", strictOff, true, nil, GroupAction{Send: true, Enabled: false}},
		{"a disable window's end", strictOff, false, nil, GroupAction{Send: true, Enabled: true}},
		{"an end while another enable window for the group is open", bedtime, false,
			[]Open{open(3, "Early nights", KindGroupEnabled, "bedtime")}, GroupAction{Skip: SkipStillOpen, Other: "Early nights"}},
		{"a start while another enable window is open", bedtime, true,
			[]Open{open(3, "Early nights", KindGroupEnabled, "bedtime")}, GroupAction{Send: true, Enabled: true}},
		{"an end while a window for another group is open", bedtime, false,
			[]Open{open(3, "Other", KindGroupEnabled, "kids")}, GroupAction{Send: true, Enabled: false}},
		{"an end while a blocking window is open", bedtime, false,
			[]Open{open(3, "Lab", KindBlockingOff, "")}, GroupAction{Send: true, Enabled: false}},
		{"a start while the opposite kind is open", bedtime, true,
			[]Open{open(1, "Bedtime", KindGroupEnabled, "bedtime"), open(4, "Off", KindGroupDisabled, "bedtime")},
			GroupAction{Skip: SkipConflict, Other: "Off"}},
		{"an end while the opposite kind is open", bedtime, false,
			[]Open{open(4, "Off", KindGroupDisabled, "bedtime")}, GroupAction{Skip: SkipConflict, Other: "Off"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := GroupEdge(tc.self, tc.start, tc.open); got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestOpenAtReaches(t *testing.T) {
	utc := zone(t, "UTC")
	rs := []Reach{
		{ID: 1, Name: "Lab", Kind: KindBlockingOff, Window: weekly(utc, weekdays, "08:00", "08:30", 0)},
		{ID: 2, Name: "Bedtime", Kind: KindGroupEnabled, Group: "bedtime", Window: weekly(utc, AllDays, "21:00", "07:00", 1)},
	}
	got := OpenAt(rs, at(t, utc, "2027-03-01 08:10"))
	if len(got) != 1 || got[0].ID != 1 || !got[0].Interval.End.Equal(at(t, utc, "2027-03-01 08:30")) {
		t.Errorf("at 08:10: %+v", got)
	}
	// Half-open: a window isn't open at its own end, but one starting then is.
	if got := OpenAt(rs, at(t, utc, "2027-03-02 07:00")); len(got) != 0 {
		t.Errorf("at 07:00: %+v", got)
	}
	if got := OpenAt(rs, at(t, utc, "2027-03-01 21:00")); len(got) != 1 || got[0].ID != 2 {
		t.Errorf("at 21:00: %+v", got)
	}
}

func TestBlockingUntil(t *testing.T) {
	utc := zone(t, "UTC")
	now := at(t, utc, "2027-03-01 08:00")
	self := Interval{now, at(t, utc, "2027-03-01 08:30")}
	blocking := func(start, end string) Open {
		return Open{Reach{Kind: KindBlockingOff}, Interval{at(t, utc, start), at(t, utc, end)}}
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		open []Open
		want string // "" when nothing is left
	}{
		{"alone", now, []Open{{Reach{Kind: KindBlockingOff}, self}}, "2027-03-01 08:30"},
		{"inside a longer window", now, []Open{blocking("2027-03-01 07:00", "2027-03-01 10:00")}, "2027-03-01 10:00"},
		{"with a shorter one", now, []Open{blocking("2027-03-01 07:00", "2027-03-01 08:15")}, "2027-03-01 08:30"},
		{"a group window doesn't count", now, []Open{{Reach{Kind: KindGroupEnabled}, Interval{now, now.Add(5 * time.Hour)}}}, "2027-03-01 08:30"},
		{"at most 24 hours", now, []Open{blocking("2027-03-01 07:00", "2027-03-02 09:00")}, "2027-03-02 08:00"},
		{"found late", at(t, utc, "2027-03-01 08:20"), nil, "2027-03-01 08:30"},
		{"found after it ended", at(t, utc, "2027-03-01 08:30"), nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BlockingUntil(tc.now, self, tc.open)
			if (tc.want != "") != ok || (ok && !got.Equal(at(t, utc, tc.want))) {
				t.Errorf("got %s, %v; want %q", got, ok, tc.want)
			}
		})
	}
}

func TestNeedsBlockingOff(t *testing.T) {
	now := time.Date(2027, 3, 1, 8, 0, 0, 0, time.UTC)
	until := now.Add(30 * time.Minute)
	d := func(m time.Duration) *time.Duration { return &m }
	for _, tc := range []struct {
		name string
		st   BlockingStatus
		want bool
	}{
		{"blocking on", BlockingStatus{}, true},
		{"off by hand, no timer", BlockingStatus{Disabled: true}, false},
		{"off with a longer timer", BlockingStatus{Disabled: true, Timer: d(time.Hour)}, false},
		{"off with the same timer, in whole seconds", BlockingStatus{Disabled: true, Timer: d(30*time.Minute - 500*time.Millisecond)}, false},
		{"off with a shorter timer", BlockingStatus{Disabled: true, Timer: d(10 * time.Minute)}, true},
	} {
		if got := NeedsBlockingOff(tc.st, now, until); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
