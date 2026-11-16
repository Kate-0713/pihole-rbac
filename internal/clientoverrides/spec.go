// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package clientoverrides

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// How long an override can last, as an admin chooses it (client_temp_max_minutes), and the shortest one.
const (
	MinMinutes     = 5
	MaxMinutes     = 365 * 24 * 60
	DefaultMinutes = 7 * 24 * 60
)

// Input limits, as the Pi-hole group and client rules allow.
const (
	MaxClientBytes = 255
	MaxGroupRunes  = 255
	MaxGroups      = 100
	MaxReasonRunes = 200
)

// Limits are the settings a start or a change is checked against.
type Limits struct {
	// Max is the longest an override can last, from its start (client_temp_max_minutes).
	Max time.Duration
	// ReasonRequired is client_temp_reason_required.
	ReasonRequired bool
}

// DefaultLimits are the limits before anyone has saved the settings.
var DefaultLimits = Limits{Max: DefaultMinutes * time.Minute, ReasonRequired: true}

func invalid(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func tooLong(field string, l Limits, format string, args ...any) *rbac.Error {
	e := invalid(field, format, args...)
	e.Details["max_minutes"] = int(l.Max / time.Minute)
	return e
}

// CheckClient checks a client as the body names it: 1 to 255 bytes of plain text, used exactly as given.
func CheckClient(client string) error {
	switch {
	case client == "" || len(client) > MaxClientBytes:
		return invalid("client", "The client must be 1 to %d bytes.", MaxClientBytes)
	case !utf8.ValidString(client) || strings.ContainsFunc(client, unicode.IsControl):
		return invalid("client", "The client can't contain control characters or line breaks.")
	}
	return nil
}

// CheckGroups checks the Pi-hole group names an override puts a client in: at most 100, each 1 to 255 characters
// of plain text with no spaces at the start or end, none twice. The list may be empty only if the Pi-hole accepts a
// client with no groups, which the caller decides.
func CheckGroups(names []string) error {
	if len(names) > MaxGroups {
		return invalid("groups", "An override can use at most %d Pi-hole groups.", MaxGroups)
	}
	for i, n := range names {
		switch {
		case n == "" || utf8.RuneCountInString(n) > MaxGroupRunes || strings.TrimSpace(n) != n:
			return invalid("groups", "A Pi-hole group name is 1 to %d characters, with no spaces at the start or end.", MaxGroupRunes)
		case !utf8.ValidString(n) || strings.ContainsFunc(n, unicode.IsControl):
			return invalid("groups", "A Pi-hole group name can't contain control characters or line breaks.")
		}
		for _, o := range names[:i] {
			if o == n {
				return invalid("groups", "The group %q is listed twice.", n)
			}
		}
	}
	return nil
}

// CheckReason checks and cleans a reason: trimmed, at most 200 characters, plain text, and given while the setting
// requires one. It is cleaned like other values that reach a notification.
func CheckReason(reason string, required bool) (string, error) {
	r := strings.TrimSpace(reason)
	switch {
	case !utf8.ValidString(r) || strings.ContainsFunc(r, unicode.IsControl):
		return "", invalid("reason", "The reason can't contain control characters or line breaks.")
	case utf8.RuneCountInString(r) > MaxReasonRunes:
		return "", invalid("reason", "The reason can be at most %d characters.", MaxReasonRunes)
	case r == "" && required:
		return "", invalid("reason", "Give a reason, 1 to %d characters.", MaxReasonRunes)
	}
	return r, nil
}

// StartEnd works out when a new override ends from exactly one of a duration in minutes and an end time. It must last
// at least 5 minutes and no more than the maximum.
func StartEnd(now time.Time, durationMinutes *int, endsAt *time.Time, l Limits) (time.Time, error) {
	var end time.Time
	switch {
	case (durationMinutes == nil) == (endsAt == nil):
		return time.Time{}, invalid("duration_minutes", "Give either duration_minutes or ends_at.")
	case durationMinutes != nil:
		if *durationMinutes < MinMinutes {
			return time.Time{}, invalid("duration_minutes", "An override lasts at least %d minutes.", MinMinutes)
		}
		if *durationMinutes > int(l.Max/time.Minute) {
			return time.Time{}, tooLong("duration_minutes", l, "An override can last at most %d minutes.", int(l.Max/time.Minute))
		}
		end = now.Add(time.Duration(*durationMinutes) * time.Minute)
	default:
		end = *endsAt
		if end.Before(now.Add(MinMinutes * time.Minute)) {
			return time.Time{}, invalid("ends_at", "An override lasts at least %d minutes.", MinMinutes)
		}
		if end.Sub(now) > l.Max {
			return time.Time{}, tooLong("ends_at", l, "An override can last at most %d minutes.", int(l.Max/time.Minute))
		}
	}
	return end, nil
}

// CheckExtend checks a new end for an override that started at startsAt: later than now, and no more than the
// maximum after the start (decided Nov 15), so extending again and again can't get round the limit.
func CheckExtend(now, startsAt, newEnd time.Time, l Limits) error {
	switch {
	case !newEnd.After(now):
		return invalid("ends_at", "The new end has to be in the future. To stop it now, end the override.")
	case newEnd.Sub(startsAt) > l.Max:
		return tooLong("ends_at", l, "An override can last at most %d minutes from when it started.", int(l.Max/time.Minute))
	}
	return nil
}

// CheckMax checks client_temp_max_minutes itself.
func CheckMax(minutes int) bool { return minutes >= MinMinutes && minutes <= MaxMinutes }
