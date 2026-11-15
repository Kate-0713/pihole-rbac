// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import "time"

// Overlapping windows are resolved per instance: the scheduler gathers the windows of every enabled schedule that
// reaches an instance (set on it, or on a mirrored group it is an enabled member of) and decides what an edge does
// there from the ones open at that moment. This file is that decision, pure, so the scheduler only gathers and sends.

// Reach is a schedule as seen from one instance it reaches.
type Reach struct {
	ID     int64
	Name   string
	Kind   Kind
	Group  string // the Pi-hole group, for the group kinds
	Window Window
}

// Open is a schedule with a window open at some moment, and that window.
type Open struct {
	Reach
	Interval Interval
}

// OpenAt returns the schedules in rs with a window open at t.
func OpenAt(rs []Reach, t time.Time) []Open {
	var out []Open
	for _, r := range rs {
		if iv, ok := r.Window.OpenAt(t); ok {
			out = append(out, Open{r, iv})
		}
	}
	return out
}

// Why an edge sends nothing to an instance.
const (
	SkipStillOpen  = "still_open"        // a group window's end while another of the same kind for the group is open
	SkipConflict   = "schedule_conflict" // windows of both group kinds for the group are open
	SkipWindowOver = "window_over"       // a blocking start found after its window ended
	SkipUnchanged  = "unchanged"         // blocking already off for at least as long, or off by hand with no timer
)

// GroupAction is what a group window's edge does on one instance.
type GroupAction struct {
	Send    bool
	Enabled bool   // the state to set when Send
	Skip    string // why nothing is sent, when !Send
	Other   string // the schedule that is still open, or in conflict
}

// GroupEdge decides a group window's edge on one instance. self is the schedule whose edge it is; open are the
// schedules open on the instance at the edge's moment (self among them at a start, not at its end). Only those for
// the same Pi-hole group count.
func GroupEdge(self Reach, start bool, open []Open) GroupAction {
	want := start == (self.Kind == KindGroupEnabled)
	var same string
	for _, o := range open {
		if o.ID == self.ID || !o.Kind.Group() || o.Group != self.Group {
			continue
		}
		if o.Kind != self.Kind {
			return GroupAction{Skip: SkipConflict, Other: o.Name}
		}
		if same == "" {
			same = o.Name
		}
	}
	if !start && same != "" {
		return GroupAction{Skip: SkipStillOpen, Other: same}
	}
	return GroupAction{Send: true, Enabled: want}
}

// BlockingUntil is when blocking should come back on, for a blocking window found open at now on one instance: the
// latest end of the blocking windows open there (open, which should include self's), at most MaxBlocking from now.
// ok is false when nothing is left of the window.
func BlockingUntil(now time.Time, self Interval, open []Open) (until time.Time, ok bool) {
	until = self.End
	for _, o := range open {
		if o.Kind == KindBlockingOff && o.Interval.End.After(until) {
			until = o.Interval.End
		}
	}
	until = minTime(until, now.Add(MaxBlocking))
	return until, until.After(now)
}

// BlockingStatus is an instance's blocking state as Pi-hole reports it.
type BlockingStatus struct {
	Disabled bool
	Timer    *time.Duration // time left before Pi-hole flips blocking back; nil with no timer running
}

// NeedsBlockingOff reports whether blocking has to be turned off on an instance so it stays off until until: not
// when it is off with no timer (turned off by hand, which sticks), nor when its timer runs at least as long.
func NeedsBlockingOff(st BlockingStatus, now, until time.Time) bool {
	if !st.Disabled {
		return true
	}
	if st.Timer == nil {
		return false
	}
	return now.Add(*st.Timer).Before(until.Add(-time.Second)) // Pi-hole reports whole seconds
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
