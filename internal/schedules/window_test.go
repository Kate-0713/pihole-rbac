// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"testing"
	"time"
)

func zone(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := LoadZone(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// at parses "2027-03-01 08:00" in loc.
func at(t *testing.T, loc *time.Location, s string) time.Time {
	t.Helper()
	v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func weekly(loc *time.Location, days int, start, end string, endDays int) Window {
	s, _ := ParseClock(start)
	e, _ := ParseClock(end)
	return Window{Repeat: RepeatWeekly, Days: days, Start: s, End: e, EndDays: endDays, Location: loc}
}

const weekdays = Monday | Tuesday | Wednesday | Thursday | Friday

func TestDayBit(t *testing.T) {
	for d, want := range map[time.Weekday]int{
		time.Monday: Monday, time.Tuesday: Tuesday, time.Saturday: Saturday, time.Sunday: Sunday,
	} {
		if got := DayBit(d); got != want {
			t.Errorf("DayBit(%s) = %d, want %d", d, got, want)
		}
	}
}

func TestParseClock(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"00:00", 0, true}, {"08:30", 510, true}, {"23:59", 1439, true},
		{"24:00", 0, false}, {"12:60", 0, false}, {"8:30", 0, false}, {"08.30", 0, false}, {"0a:00", 0, false}, {"", 0, false},
	} {
		got, ok := ParseClock(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ParseClock(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
		if ok && FormatClock(got) != tc.in {
			t.Errorf("FormatClock(%d) = %q, want %q", got, FormatClock(got), tc.in)
		}
	}
}

func TestOccurrences(t *testing.T) {
	utc := zone(t, "UTC")
	london := zone(t, "Europe/London")
	// 2027-03-01 is a Monday. London's clocks go forward at 01:00 on 2027-03-28 and back at 02:00 on 2027-10-31.
	for _, tc := range []struct {
		name     string
		w        Window
		from, to string
		loc      *time.Location
		want     [][2]string // in loc
	}{
		{
			name: "weekdays in a week", w: weekly(utc, weekdays, "08:00", "08:30", 0), loc: utc,
			from: "2027-03-01 00:00", to: "2027-03-08 00:00",
			want: [][2]string{
				{"2027-03-01 08:00", "2027-03-01 08:30"}, {"2027-03-02 08:00", "2027-03-02 08:30"},
				{"2027-03-03 08:00", "2027-03-03 08:30"}, {"2027-03-04 08:00", "2027-03-04 08:30"},
				{"2027-03-05 08:00", "2027-03-05 08:30"},
			},
		},
		{
			name: "past midnight, started the day before from", w: weekly(london, Monday, "21:00", "07:00", 1), loc: london,
			from: "2027-03-02 02:00", to: "2027-03-02 03:00",
			want: [][2]string{{"2027-03-01 21:00", "2027-03-02 07:00"}},
		},
		{
			name: "a weekend, Friday to Monday", w: weekly(utc, Friday, "18:00", "07:00", 3), loc: utc,
			from: "2027-03-06 12:00", to: "2027-03-06 13:00",
			want: [][2]string{{"2027-03-05 18:00", "2027-03-08 07:00"}},
		},
		{
			name: "a whole week, open from 8 days before", w: weekly(utc, Monday, "00:00", "00:00", 7), loc: utc,
			from: "2027-03-07 12:00", to: "2027-03-07 13:00",
			want: [][2]string{{"2027-03-01 00:00", "2027-03-08 00:00"}},
		},
		{
			name: "a start the clocks skip comes an hour later", w: weekly(london, Sunday, "01:30", "03:00", 0), loc: london,
			from: "2027-03-28 00:00", to: "2027-03-29 00:00",
			want: [][2]string{{"2027-03-28 02:30", "2027-03-28 03:00"}},
		},
		{
			name: "an end before the skipped start takes the nominal length", w: weekly(london, Sunday, "01:30", "02:10", 0), loc: london,
			from: "2027-03-28 00:00", to: "2027-03-29 00:00",
			want: [][2]string{{"2027-03-28 02:30", "2027-03-28 03:10"}},
		},
		{
			name: "a one-off", loc: utc, from: "2027-03-01 00:00", to: "2027-03-02 00:00",
			w:    Window{Repeat: RepeatOnce, StartsAt: at(t, utc, "2027-03-01 10:00"), EndsAt: at(t, utc, "2027-03-01 11:00")},
			want: [][2]string{{"2027-03-01 10:00", "2027-03-01 11:00"}},
		},
		{
			name: "a one-off outside the span", loc: utc, from: "2027-03-02 00:00", to: "2027-03-03 00:00",
			w: Window{Repeat: RepeatOnce, StartsAt: at(t, utc, "2027-03-01 10:00"), EndsAt: at(t, utc, "2027-03-01 11:00")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.w.Occurrences(at(t, tc.loc, tc.from), at(t, tc.loc, tc.to))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d windows %v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if !got[i].Start.Equal(at(t, tc.loc, w[0])) || !got[i].End.Equal(at(t, tc.loc, w[1])) {
					t.Errorf("window %d is %s to %s, want %s to %s", i, got[i].Start.In(tc.loc), got[i].End.In(tc.loc), w[0], w[1])
				}
			}
		})
	}
}

func TestDaylightSavingLength(t *testing.T) {
	london := zone(t, "Europe/London")
	w := weekly(london, Saturday, "21:00", "07:00", 1)
	// The night the clocks go back is an hour longer, and the night they go forward an hour shorter.
	for _, tc := range []struct {
		day  string
		want time.Duration
	}{{"2027-10-30 22:00", 11 * time.Hour}, {"2027-03-27 22:00", 9 * time.Hour}, {"2027-03-06 22:00", 10 * time.Hour}} {
		iv, ok := w.OpenAt(at(t, london, tc.day))
		if !ok || iv.End.Sub(iv.Start) != tc.want {
			t.Errorf("%s: %v (open %v), want %s", tc.day, iv.End.Sub(iv.Start), ok, tc.want)
		}
	}
}

func TestEdges(t *testing.T) {
	utc := zone(t, "UTC")
	lab := weekly(utc, weekdays, "08:00", "08:30", 0)
	daily := weekly(utc, AllDays, "08:00", "08:00", 1) // each window ends as the next begins
	once := Window{Repeat: RepeatOnce, StartsAt: at(t, utc, "2027-03-03 10:00"), EndsAt: at(t, utc, "2027-03-03 11:00")}
	type edge struct {
		at    string
		start bool
	}
	for _, tc := range []struct {
		name         string
		w            Window
		now          string
		latest, next *edge
	}{
		{"during a window", lab, "2027-03-01 08:15", &edge{"2027-03-01 08:00", true}, &edge{"2027-03-01 08:30", false}},
		{"exactly at a start", lab, "2027-03-01 08:00", &edge{"2027-03-01 08:00", true}, &edge{"2027-03-01 08:30", false}},
		{"exactly at an end", lab, "2027-03-01 08:30", &edge{"2027-03-01 08:30", false}, &edge{"2027-03-02 08:00", true}},
		{"Monday morning, after the weekend", lab, "2027-03-01 07:00", &edge{"2027-02-26 08:30", false}, &edge{"2027-03-01 08:00", true}},
		{"an end and a start together: the start", daily, "2027-03-02 08:00", &edge{"2027-03-02 08:00", true}, &edge{"2027-03-03 08:00", true}},
		{"before a one-off", once, "2027-03-02 12:00", nil, &edge{"2027-03-03 10:00", true}},
		{"after a one-off", once, "2027-03-04 12:00", &edge{"2027-03-03 11:00", false}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := at(t, utc, tc.now)
			check := func(what string, got Edge, ok bool, want *edge) {
				t.Helper()
				if (want != nil) != ok {
					t.Fatalf("%s: found %v (%v), want %v", what, ok, got, want)
				}
				if want != nil && (!got.At.Equal(at(t, utc, want.at)) || got.Start != want.start) {
					t.Errorf("%s: %s %s, want %s %v", what, got.Name(), got.At, want.at, want.start)
				}
			}
			e, ok := tc.w.LatestEdge(now)
			check("latest", e, ok, tc.latest)
			e, ok = tc.w.NextEdge(now)
			check("next", e, ok, tc.next)
		})
	}
}

func TestOverlap(t *testing.T) {
	utc := zone(t, "UTC")
	now := at(t, utc, "2027-03-01 00:00") // a Monday
	bedtime := weekly(utc, Monday, "21:00", "07:00", 1)
	for _, tc := range []struct {
		name string
		a, b Window
		want string // "" for none
	}{
		{"across midnight into the next morning", bedtime, weekly(utc, Tuesday, "06:00", "08:00", 0), "2027-03-02 06:00"},
		{"touching only", bedtime, weekly(utc, Tuesday, "07:00", "08:00", 0), ""},
		{"different days", bedtime, weekly(utc, Thursday, "06:00", "08:00", 0), ""},
		{"a weekend and a Sunday afternoon", weekly(utc, Friday, "18:00", "07:00", 3), weekly(utc, Sunday, "14:00", "16:00", 0), "2027-03-07 14:00"},
		{"a one-off inside a weekly window", bedtime,
			Window{Repeat: RepeatOnce, StartsAt: at(t, utc, "2027-03-08 22:00"), EndsAt: at(t, utc, "2027-03-08 23:00")}, "2027-03-08 22:00"},
		{"a one-off before the weekly window", bedtime,
			Window{Repeat: RepeatOnce, StartsAt: at(t, utc, "2027-03-01 10:00"), EndsAt: at(t, utc, "2027-03-01 11:00")}, ""},
		{"a weekly window already open now", weekly(utc, Sunday, "20:00", "08:00", 1), weekly(utc, Monday, "06:00", "07:00", 0), "2027-03-01 06:00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Overlap(tc.a, tc.b, now)
			if (tc.want != "") != ok || (ok && !got.Equal(at(t, utc, tc.want))) {
				t.Errorf("Overlap = %s, %v; want %q", got, ok, tc.want)
			}
			if back, ok2 := Overlap(tc.b, tc.a, now); ok2 != ok || !back.Equal(got) {
				t.Errorf("Overlap isn't symmetric: %s, %v", back, ok2)
			}
		})
	}
}
