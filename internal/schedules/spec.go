// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package schedules

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// Spec is what someone saves: a schedule's name, what it does and when. The target and the checks that need a
// Pi-hole (the group exists and isn't Default) or the other schedules (overlaps) are made by the caller.
type Spec struct {
	Name        string
	Kind        Kind
	PiholeGroup string // the group kinds only
	Window      Window
}

// Limits are the settings a save is checked against.
type Limits struct {
	// MaxGroupWindow is the longest a group window can be (schedule_group_window_max_minutes).
	MaxGroupWindow time.Duration
}

// Group window lengths an admin can choose between, and the default.
const (
	MinGroupWindowMinutes     = 5
	MaxGroupWindowMinutes     = 365 * minutesPerDay
	DefaultGroupWindowMinutes = minutesPerDay
)

const (
	maxName      = 100
	maxGroupName = 255 // as the Pi-hole group rules allow
)

func invalid(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

// CheckName checks a schedule's name: 1 to 100 characters, no control characters and no leading or trailing
// whitespace.
func CheckName(name string) error {
	switch {
	case name == "" || utf8.RuneCountInString(name) > maxName:
		return invalid("name", "A schedule's name is 1 to %d characters.", maxName)
	case !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl):
		return invalid("name", "A schedule's name can't contain control characters.")
	case strings.TrimSpace(name) != name:
		return invalid("name", "A schedule's name can't start or end with a space.")
	}
	return nil
}

// ParseClock reads "HH:MM" (24-hour) as minutes after midnight.
func ParseClock(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, m := 0, 0
	for i, c := range []byte(s) {
		if i == 2 {
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		if i < 2 {
			h = h*10 + int(c-'0')
		} else {
			m = m*10 + int(c-'0')
		}
	}
	if h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// FormatClock writes minutes after midnight as "HH:MM".
func FormatClock(min int) string { return fmt.Sprintf("%02d:%02d", min/60, min%60) }

// LoadZone loads a schedule's time zone. "Local" isn't accepted: it would mean the server's own zone, which differs
// between hosts and is UTC in the Docker image.
func LoadZone(name string) (*time.Location, error) {
	if name == "" || name == "Local" || len(name) > 64 {
		return nil, fmt.Errorf("time zone %q not allowed", name)
	}
	return time.LoadLocation(name)
}

// MaxLength is the longest a window of kind k can be under l, weekly or not.
func (l Limits) MaxLength(k Kind, r Repeat) time.Duration {
	max := MaxBlocking
	if k.Group() {
		max = l.MaxGroupWindow
		if max <= 0 {
			max = DefaultGroupWindowMinutes * time.Minute
		}
	}
	if r == RepeatWeekly {
		max = min(max, MaxWeekly)
	}
	return max
}

// OverLimit reports whether the schedule's window is longer than l allows now, as a schedule saved before the
// setting was lowered can be. It keeps running, but any edit must bring it within the limit.
func (s Spec) OverLimit(l Limits) bool {
	return s.Window.Nominal() > l.MaxLength(s.Kind, s.Window.Repeat)
}

// Check checks a spec saved at now. It refuses with a validation error naming the field.
func (s Spec) Check(now time.Time, l Limits) error {
	if err := CheckName(s.Name); err != nil {
		return err
	}
	if !s.Kind.Valid() {
		return invalid("kind", "The kind is blocking_off, group_enabled or group_disabled.")
	}
	switch {
	case s.Kind.Group() && s.PiholeGroup == "":
		return invalid("pihole_group", "A group window needs a Pi-hole group.")
	case s.Kind.Group() && (len(s.PiholeGroup) > maxGroupName || strings.ContainsFunc(s.PiholeGroup, unicode.IsControl)):
		return invalid("pihole_group", "That isn't a Pi-hole group name.")
	case !s.Kind.Group() && s.PiholeGroup != "":
		return invalid("pihole_group", "A blocking window doesn't name a Pi-hole group.")
	}
	w := s.Window
	switch w.Repeat {
	case RepeatWeekly:
		switch {
		case w.Days&AllDays == 0 || w.Days&^AllDays != 0:
			return invalid("days", "Choose at least one day.")
		case w.Start < 0 || w.Start >= minutesPerDay:
			return invalid("start", "The start is HH:MM, from 00:00 to 23:59.")
		case w.End < 0 || w.End >= minutesPerDay:
			return invalid("end", "The end is HH:MM, from 00:00 to 23:59.")
		case w.EndDays < 0 || w.EndDays > 7:
			return invalid("end_days", "A window ends 0 to 7 days after the day it starts.")
		case w.Location == nil:
			return invalid("time_zone", "A weekly schedule needs a time zone, such as Europe/London or UTC.")
		case w.Nominal() <= 0:
			return invalid("end", "The window has to end after it starts: for a window past midnight, end it the next day.")
		case w.Nominal() > shortestGap(w.Days):
			return invalid("end_days", "The window is longer than the time until it starts again, so it would overlap itself.")
		}
	case RepeatOnce:
		switch {
		case w.StartsAt.IsZero():
			return invalid("starts_at", "A one-off schedule needs a start.")
		case !w.StartsAt.After(now):
			return invalid("starts_at", "A one-off schedule has to start in the future.")
		case !w.EndsAt.After(w.StartsAt):
			return invalid("ends_at", "The window has to end after it starts.")
		}
	default:
		return invalid("repeat", "A schedule repeats weekly or happens once.")
	}
	if max := l.MaxLength(s.Kind, w.Repeat); w.Nominal() > max {
		field := "ends_at"
		if w.Repeat == RepeatWeekly {
			field = "end_days"
		}
		err := invalid(field, "The window can be at most %s long.", describeLength(max))
		err.Details["max_minutes"] = int(max / time.Minute)
		return err
	}
	return nil
}

// describeLength names a length in words: "24 hours", "7 days", "1 day 12 hours", "1 hour 30 minutes".
func describeLength(d time.Duration) string {
	m := int(d / time.Minute)
	days, hours, mins := m/minutesPerDay, m%minutesPerDay/60, m%60
	var parts []string
	unit := func(n int, one, many string) {
		if n == 1 {
			parts = append(parts, "1 "+one)
		} else if n > 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, many))
		}
	}
	if days == 1 && hours == 0 && mins == 0 {
		return "24 hours"
	}
	unit(days, "day", "days")
	unit(hours, "hour", "hours")
	unit(mins, "minute", "minutes")
	if len(parts) == 0 {
		return "0 minutes"
	}
	return strings.Join(parts, " ")
}
