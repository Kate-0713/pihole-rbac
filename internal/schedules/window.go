// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package schedules runs schedules: blocking turned off, or a Pi-hole group turned on or off, for a window that
// repeats weekly or happens once. This file holds the window maths: when a schedule's windows happen and which edge
// (a start or an end) is due. It is pure, so it is tested with times given directly.
package schedules

import (
	"slices"
	"time"
)

// Kind is what a schedule does during its window.
type Kind string

const (
	KindBlockingOff   Kind = "blocking_off"   // blocking off, through Pi-hole's own timer
	KindGroupEnabled  Kind = "group_enabled"  // a Pi-hole group enabled at the start, disabled at the end
	KindGroupDisabled Kind = "group_disabled" // the reverse
)

// Valid reports whether k is one of the kinds.
func (k Kind) Valid() bool {
	return k == KindBlockingOff || k == KindGroupEnabled || k == KindGroupDisabled
}

// Group reports whether k acts on a Pi-hole group.
func (k Kind) Group() bool { return k == KindGroupEnabled || k == KindGroupDisabled }

// Repeat is how often a schedule's window happens.
type Repeat string

const (
	RepeatWeekly Repeat = "weekly"
	RepeatOnce   Repeat = "once"
)

// Days of the week as Window.Days bits, Monday first, as the API and the table have them.
const (
	Monday = 1 << iota
	Tuesday
	Wednesday
	Thursday
	Friday
	Saturday
	Sunday

	AllDays = 1<<7 - 1
)

// DayBit is the Window.Days bit for d.
func DayBit(d time.Weekday) int { return 1 << ((int(d) + 6) % 7) }

const (
	minutesPerDay = 24 * 60
	// MaxWeekly is the longest a weekly window can be: it repeats every week.
	MaxWeekly = 7 * 24 * time.Hour
	// MaxBlocking is the longest a blocking window can be: Pi-hole's timer, as the API limits it.
	MaxBlocking = 24 * time.Hour
)

// Window is when a schedule's windows happen. A weekly window starts on each day in Days at Start (minutes after
// midnight in Location) and ends EndDays days later at End; there is no implicit wrap past midnight, so 21:00 to
// 07:00 is EndDays 1. A one-off window runs from StartsAt to EndsAt.
type Window struct {
	Repeat Repeat

	Days       int // weekly: a bitmask of Monday ... Sunday
	Start, End int // weekly: minutes after midnight, 0 to 1439
	EndDays    int // weekly: 0 to 7
	Location   *time.Location

	StartsAt, EndsAt time.Time // once
}

// Interval is one window: from Start, up to but not including End.
type Interval struct{ Start, End time.Time }

// Contains reports whether t is in the window.
func (iv Interval) Contains(t time.Time) bool { return !t.Before(iv.Start) && t.Before(iv.End) }

// Overlaps reports whether the two windows share a moment.
func (iv Interval) Overlaps(o Interval) bool { return iv.Start.Before(o.End) && o.Start.Before(iv.End) }

// Nominal is a window's length as entered: for a weekly window, EndDays days plus End minus Start, whatever daylight
// saving does to a particular week. It can be zero or negative for a weekly window that doesn't validate.
func (w Window) Nominal() time.Duration {
	if w.Repeat == RepeatOnce {
		return w.EndsAt.Sub(w.StartsAt)
	}
	return time.Duration(w.EndDays*minutesPerDay+w.End-w.Start) * time.Minute
}

// Occurrences returns the windows that end after from and start before to, in order. A weekly window's times are
// worked out in its zone, so a start the clocks skip comes later, as time.Date normalises it. If daylight saving
// would put a window's end at or before its start, the end is its nominal length after the start instead.
func (w Window) Occurrences(from, to time.Time) []Interval {
	var out []Interval
	add := func(iv Interval) {
		if iv.End.After(from) && iv.Start.Before(to) {
			out = append(out, iv)
		}
	}
	if w.Repeat == RepeatOnce {
		add(Interval{w.StartsAt, w.EndsAt})
		return out
	}
	if w.Location == nil || w.Days&AllDays == 0 || w.Nominal() <= 0 {
		return nil
	}
	// A window starting up to 8 days before from can still be open at from: at most 7 days long, and a day more
	// covers the zone's offset.
	local := from.In(w.Location)
	y, m, d := local.Date()
	for i := -8; ; i++ {
		day := time.Date(y, m, d+i, 12, 0, 0, 0, w.Location)
		if w.Days&DayBit(day.Weekday()) == 0 {
			if !day.Before(to.Add(24 * time.Hour)) {
				break
			}
			continue
		}
		start := time.Date(y, m, d+i, w.Start/60, w.Start%60, 0, 0, w.Location)
		if !start.Before(to) {
			break
		}
		end := time.Date(y, m, d+i+w.EndDays, w.End/60, w.End%60, 0, 0, w.Location)
		if !end.After(start) {
			end = start.Add(w.Nominal())
		}
		add(Interval{start, end})
	}
	return out
}

// OpenAt returns the window open at t, if any.
func (w Window) OpenAt(t time.Time) (Interval, bool) {
	for _, iv := range w.Occurrences(t, t.Add(time.Nanosecond)) {
		if iv.Contains(t) {
			return iv, true
		}
	}
	return Interval{}, false
}

// Edge is a window's start or end.
type Edge struct {
	At     time.Time
	Start  bool     // a start; otherwise an end
	Window Interval // the window it starts or ends
}

// Name is "start" or "end", as the table stores it.
func (e Edge) Name() string {
	if e.Start {
		return "start"
	}
	return "end"
}

// later orders edges by time, with a start after an end at the same moment: when one window ends as the next
// begins, the start is what applies.
func later(a, b Edge) bool {
	if !a.At.Equal(b.At) {
		return a.At.After(b.At)
	}
	return a.Start && !b.Start
}

// edges returns the edges of the windows that overlap from to to.
func (w Window) edges(from, to time.Time) []Edge {
	var out []Edge
	for _, iv := range w.Occurrences(from, to) {
		out = append(out, Edge{iv.Start, true, iv}, Edge{iv.End, false, iv})
	}
	return out
}

// LatestEdge returns the latest edge at or before t.
func (w Window) LatestEdge(t time.Time) (Edge, bool) {
	var best Edge
	found := false
	for _, e := range w.edges(t.Add(-2*MaxWeekly), t.Add(time.Nanosecond)) {
		if e.At.After(t) {
			continue
		}
		if !found || later(e, best) {
			best, found = e, true
		}
	}
	return best, found
}

// NextEdge returns the first edge after t. When an end and a start fall at the same moment, it is the start.
func (w Window) NextEdge(t time.Time) (Edge, bool) {
	var best Edge
	found := false
	for _, e := range w.edges(t, t.Add(2*MaxWeekly+24*time.Hour)) {
		if !e.At.After(t) {
			continue
		}
		if !found || e.At.Before(best.At) || (e.At.Equal(best.At) && e.Start) {
			best, found = e, true
		}
	}
	return best, found
}

// selectedDays returns the offsets (0 for Monday ... 6 for Sunday) of the days in days.
func selectedDays(days int) []int {
	var out []int
	for i := range 7 {
		if days&(1<<i) != 0 {
			out = append(out, i)
		}
	}
	return out
}

// shortestGap is the shortest time from one selected day to the next selected one, a week when only one is.
func shortestGap(days int) time.Duration {
	sel := selectedDays(days)
	if len(sel) == 0 {
		return 0
	}
	gap := 7
	for i, d := range sel {
		next := sel[(i+1)%len(sel)]
		g := (next - d + 7) % 7
		if g == 0 {
			g = 7
		}
		gap = min(gap, g)
	}
	return time.Duration(gap) * 24 * time.Hour
}

// overlapSpan is how far ahead two windows are compared: a one-off window's own span, or two weeks for two weekly
// ones, which covers every pairing of their weekly patterns.
func overlapSpan(a, b Window, now time.Time) (from, to time.Time) {
	from, to = now, now.Add(2*MaxWeekly)
	for _, w := range []Window{a, b} {
		if w.Repeat == RepeatOnce && w.EndsAt.Before(to) {
			to = w.EndsAt
		}
	}
	return from, to
}

// Overlap returns the first moment from now on when a window of a and a window of b are both open, if there is one.
func Overlap(a, b Window, now time.Time) (time.Time, bool) {
	from, to := overlapSpan(a, b, now)
	if !to.After(from) {
		return time.Time{}, false
	}
	ao, bo := a.Occurrences(from, to), b.Occurrences(from, to)
	var first time.Time
	found := false
	for _, x := range ao {
		for _, y := range bo {
			if !x.Overlaps(y) {
				continue
			}
			at := latestOf(x.Start, y.Start, from)
			if !found || at.Before(first) {
				first, found = at, true
			}
		}
	}
	return first, found
}

func latestOf(ts ...time.Time) time.Time {
	return slices.MaxFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
}
