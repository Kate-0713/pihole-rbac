// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginsettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	_ "time/tzdata" // the schedule's time zone must load on a host without zone files, such as the distroless image

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientoverrides"
	"github.com/Kate-0713/pihole-rbac/internal/localdns"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/schedules"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// GeneralKey is the settings row holding the general settings.
const GeneralKey = "general"

// General are the general settings: how long sessions last, how long audit rows are kept, when client reset runs, and
// whether file: lists can be added.
type General struct {
	SessionLifetimeMinutes int `json:"session_lifetime_minutes"` // absolute, from login
	IdleTimeoutMinutes     int `json:"idle_timeout_minutes"`     // since the last request
	// AuditRetentionDays is how long audit rows are kept. Rows saved before the setting existed have none, which loads
	// as the default.
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
	// ClientReset is the client reset schedule. Rows saved before the setting existed have none, which loads as
	// DefaultResetSchedule.
	ClientReset *ResetSchedule `json:"client_reset_schedule,omitempty"`
	// AllowFileLists says whether file: lists can be added. Rows saved before the setting existed have none, which
	// loads as off. On a save, nil keeps it as it is.
	AllowFileLists *bool `json:"allow_file_lists,omitempty"`
	// LocalDNSReasonRequired says whether a local DNS change needs a reason. Rows saved before the setting existed
	// have none, which loads as on. On a save, nil keeps it as it is.
	LocalDNSReasonRequired *bool `json:"localdns_reason_required,omitempty"`
	// LocalDNSExtraDomains are directory domains a local DNS name is checked against, besides the LDAP base DN's.
	// Rows saved before the setting existed have none, which loads as empty. On a save, nil keeps them as they are.
	LocalDNSExtraDomains *[]string `json:"localdns_extra_domains,omitempty"`
	// ScheduleGroupWindowMaxMinutes is the longest a schedule's Pi-hole group window can be. Rows saved before the
	// setting existed have none, which loads as a day. On a save, nil keeps it as it is.
	ScheduleGroupWindowMaxMinutes *int `json:"schedule_group_window_max_minutes,omitempty"`
	// ClientTempMaxMinutes is the longest a temporary client group change can last, from its start. Rows saved before
	// the setting existed have none, which loads as 7 days. On a save, nil keeps it as it is.
	ClientTempMaxMinutes *int `json:"client_temp_max_minutes,omitempty"`
	// ClientTempReasonRequired says whether starting a temporary client group change needs a reason. Rows saved before
	// the setting existed have none, which loads as on. On a save, nil keeps it as it is.
	ClientTempReasonRequired *bool `json:"client_temp_reason_required,omitempty"`
}

// ResetSchedule is when client reset runs by itself: daily at Time ("HH:MM", 24-hour) in TimeZone (an IANA name),
// when Enabled. Runs on demand don't depend on it.
type ResetSchedule struct {
	Enabled  bool   `json:"enabled"`
	Time     string `json:"time"`
	TimeZone string `json:"time_zone"`
}

// DefaultResetSchedule is the schedule until one is saved: off, with 03:00 UTC ready to switch on.
var DefaultResetSchedule = ResetSchedule{Time: "03:00", TimeZone: "UTC"}

var clockPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate checks the time and the time zone. "Local" isn't accepted: it would mean the server's own zone, which
// differs between hosts and is UTC in the Docker image.
func (r ResetSchedule) Validate() error {
	if !clockPattern.MatchString(r.Time) {
		return validation("client_reset_schedule.time", "The time is HH:MM, from 00:00 to 23:59.")
	}
	if _, err := r.Location(); err != nil {
		return validation("client_reset_schedule.time_zone", "%q isn't a time zone this server knows, such as Europe/London or UTC.", r.TimeZone)
	}
	return nil
}

// Location loads the schedule's time zone.
func (r ResetSchedule) Location() (*time.Location, error) {
	if r.TimeZone == "" || r.TimeZone == "Local" || len(r.TimeZone) > 64 {
		return nil, fmt.Errorf("time zone %q not allowed", r.TimeZone)
	}
	return time.LoadLocation(r.TimeZone)
}

// Clock returns the schedule's hour and minute. The time must be valid.
func (r ResetSchedule) Clock() (hour, minute int) {
	return int(r.Time[0]-'0')*10 + int(r.Time[1]-'0'), int(r.Time[3]-'0')*10 + int(r.Time[4]-'0')
}

func (g General) schedule() ResetSchedule {
	if g.ClientReset == nil {
		return DefaultResetSchedule
	}
	return *g.ClientReset
}

// The allowed ranges, in minutes. The idle timeout can't be longer than the lifetime, since it would never apply.
const (
	MinLifetimeMinutes = 15
	MaxLifetimeMinutes = 30 * 24 * 60
	MinIdleMinutes     = 5
	MaxIdleMinutes     = 24 * 60

	DefaultRetentionDays = 365
	MinRetentionDays     = 30
	MaxRetentionDays     = 3650
)

// Validate checks the ranges. The error is a validation refusal naming the field.
func (g General) Validate() error {
	switch {
	case g.SessionLifetimeMinutes < MinLifetimeMinutes || g.SessionLifetimeMinutes > MaxLifetimeMinutes:
		return validation("session_lifetime_minutes", "A session can last %d minutes to %d days.", MinLifetimeMinutes, MaxLifetimeMinutes/(24*60))
	case g.IdleTimeoutMinutes < MinIdleMinutes || g.IdleTimeoutMinutes > MaxIdleMinutes:
		return validation("idle_timeout_minutes", "The idle timeout is %d minutes to %d hours.", MinIdleMinutes, MaxIdleMinutes/60)
	case g.IdleTimeoutMinutes > g.SessionLifetimeMinutes:
		return validation("idle_timeout_minutes", "The idle timeout can't be longer than the session lifetime.")
	case g.AuditRetentionDays < MinRetentionDays || g.AuditRetentionDays > MaxRetentionDays:
		return validation("audit_retention_days", "Audit entries can be kept for %d to %d days.", MinRetentionDays, MaxRetentionDays)
	}
	if m := g.ScheduleGroupWindowMaxMinutes; m != nil && (*m < schedules.MinGroupWindowMinutes || *m > schedules.MaxGroupWindowMinutes) {
		return validation("schedule_group_window_max_minutes", "A group window can be limited to %d minutes to %d days.",
			schedules.MinGroupWindowMinutes, schedules.MaxGroupWindowMinutes/(24*60))
	}
	if m := g.ClientTempMaxMinutes; m != nil && !clientoverrides.CheckMax(*m) {
		return validation("client_temp_max_minutes", "A temporary client change can be limited to %d minutes to %d days.",
			clientoverrides.MinMinutes, clientoverrides.MaxMinutes/(24*60))
	}
	if g.LocalDNSExtraDomains != nil {
		if _, err := localdns.CheckExtraDomains(*g.LocalDNSExtraDomains); err != nil {
			var fe *localdns.FieldError
			if errors.As(err, &fe) {
				return validation(fe.Field, "%s.", fe.Message)
			}
			return err
		}
	}
	return g.schedule().Validate()
}

func (g General) durations() (lifetime, idle time.Duration) {
	return time.Duration(g.SessionLifetimeMinutes) * time.Minute, time.Duration(g.IdleTimeoutMinutes) * time.Minute
}

// SessionLifetimes is what the general settings change in the session store.
type SessionLifetimes interface {
	SetLifetimes(lifetime, idle time.Duration)
	Lifetimes() (lifetime, idle time.Duration)
}

// GeneralView is the general settings as the settings page shows them. UpdatedAt is zero until they are saved.
type GeneralView struct {
	General
	UpdatedAt time.Time
	UpdatedBy string
}

// loadGeneral reads the general settings at startup and applies them to the sessions. A saved value that doesn't
// validate stops startup, as the login settings do.
func (s *Service) loadGeneral(ctx context.Context, q *db.Queries) error {
	row, err := q.GetSetting(ctx, GeneralKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var g General
	if err := json.Unmarshal([]byte(row.Value), &g); err != nil {
		return fmt.Errorf("settings %q: %w", GeneralKey, err)
	}
	if g.AuditRetentionDays == 0 {
		g.AuditRetentionDays = DefaultRetentionDays
	}
	if err := g.Validate(); err != nil {
		return fmt.Errorf("settings %q: %w", GeneralKey, err)
	}
	s.generalAt, s.generalBy = store.FromMillis(row.UpdatedAt), row.UpdatedBy
	s.retention = g.AuditRetentionDays
	s.schedule = g.schedule()
	s.allowFile = g.AllowFileLists != nil && *g.AllowFileLists
	s.reasonOptional = g.LocalDNSReasonRequired != nil && !*g.LocalDNSReasonRequired
	s.groupWindowMax = 0
	if g.ScheduleGroupWindowMaxMinutes != nil {
		s.groupWindowMax = *g.ScheduleGroupWindowMaxMinutes
	}
	s.clientTempMax = 0
	if g.ClientTempMaxMinutes != nil {
		s.clientTempMax = *g.ClientTempMaxMinutes
	}
	s.clientTempReasonOptional = g.ClientTempReasonRequired != nil && !*g.ClientTempReasonRequired
	s.extraDomains = nil
	if g.LocalDNSExtraDomains != nil {
		s.extraDomains, _ = localdns.CheckExtraDomains(*g.LocalDNSExtraDomains) // checked by Validate
	}
	if s.Sessions != nil {
		s.Sessions.SetLifetimes(g.durations())
	}
	return nil
}

// LocalDNSReasonRequired reports whether a local DNS change needs a reason, saved or default (on).
func (s *Service) LocalDNSReasonRequired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.reasonOptional
}

// LocalDNSExtraDomains returns the extra directory domains, saved or default (none), lowercased.
func (s *Service) LocalDNSExtraDomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.extraDomains)
}

// ScheduleLimits returns the limits a schedule is saved against: the group window maximum, saved or default (a day).
func (s *Service) ScheduleLimits() schedules.Limits {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return schedules.Limits{MaxGroupWindow: time.Duration(s.groupWindowMaxMinutes()) * time.Minute}
}

// ClientOverrideLimits returns the limits a temporary client group change is checked against: the maximum duration
// (saved or default, 7 days) and whether a reason is required (saved or default, yes).
func (s *Service) ClientOverrideLimits() clientoverrides.Limits {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clientoverrides.Limits{Max: time.Duration(s.clientTempMaxMinutes()) * time.Minute, ReasonRequired: !s.clientTempReasonOptional}
}

// clientTempMaxMinutes is the saved maximum for temporary client changes, or the default. s.mu must be held.
func (s *Service) clientTempMaxMinutes() int {
	if s.clientTempMax == 0 {
		return clientoverrides.DefaultMinutes
	}
	return s.clientTempMax
}

// groupWindowMaxMinutes is the saved group window maximum, or the default. s.mu must be held.
func (s *Service) groupWindowMaxMinutes() int {
	if s.groupWindowMax == 0 {
		return schedules.DefaultGroupWindowMinutes
	}
	return s.groupWindowMax
}

// LDAPBaseDN returns the LDAP settings' base DN, or "" when there are none.
func (s *Service) LDAPBaseDN() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ldap == nil {
		return ""
	}
	return s.ldap.BaseDN
}

// AllowFileLists reports whether file: lists can be added, saved or default (off).
func (s *Service) AllowFileLists() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowFile
}

// ResetSchedule returns the client reset schedule, saved or default.
func (s *Service) ResetSchedule() ResetSchedule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.schedule.Time == "" {
		return DefaultResetSchedule
	}
	return s.schedule
}

// AuditRetentionDays returns how many days audit rows are kept, saved or default.
func (s *Service) AuditRetentionDays() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.retention == 0 {
		return DefaultRetentionDays
	}
	return s.retention
}

// General returns the current general settings: the session store's lifetimes and the audit retention, saved or
// default.
func (s *Service) General() GeneralView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lifetime, idle := auth.DefaultLifetime, auth.DefaultIdleTimeout
	if s.Sessions != nil {
		lifetime, idle = s.Sessions.Lifetimes()
	}
	retention := s.retention
	if retention == 0 {
		retention = DefaultRetentionDays
	}
	schedule := s.schedule
	if schedule.Time == "" {
		schedule = DefaultResetSchedule
	}
	allowFile, reasonRequired := s.allowFile, !s.reasonOptional
	extra := slices.Clone(s.extraDomains)
	if extra == nil {
		extra = []string{}
	}
	groupWindowMax := s.groupWindowMaxMinutes()
	clientTempMax, clientTempReason := s.clientTempMaxMinutes(), !s.clientTempReasonOptional
	return GeneralView{
		General: General{
			SessionLifetimeMinutes: int(lifetime / time.Minute), IdleTimeoutMinutes: int(idle / time.Minute),
			AuditRetentionDays: retention, ClientReset: &schedule, AllowFileLists: &allowFile,
			LocalDNSReasonRequired: &reasonRequired, LocalDNSExtraDomains: &extra,
			ScheduleGroupWindowMaxMinutes: &groupWindowMax,
			ClientTempMaxMinutes:          &clientTempMax, ClientTempReasonRequired: &clientTempReason,
		},
		UpdatedAt: s.generalAt, UpdatedBy: s.generalBy,
	}
}

// SaveGeneral saves the general settings and applies them: a new lifetime to sessions started from now on, a new
// idle timeout to every session at once, and a new audit retention at the next prune, which RetentionChanged brings
// forward. A nil ClientReset keeps the schedule as it is. It needs settings.manage, and is audited as settings_update.
func (s *Service) SaveGeneral(ctx context.Context, a rbac.Actor, g General) error {
	if err := g.Validate(); err != nil {
		return err
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	before := s.General().General
	var changed []string
	if before.SessionLifetimeMinutes != g.SessionLifetimeMinutes {
		changed = append(changed, "session_lifetime_minutes")
	}
	if before.IdleTimeoutMinutes != g.IdleTimeoutMinutes {
		changed = append(changed, "idle_timeout_minutes")
	}
	if before.AuditRetentionDays != g.AuditRetentionDays {
		changed = append(changed, "audit_retention_days")
	}
	if g.ClientReset == nil {
		g.ClientReset = before.ClientReset // a save that leaves the schedule out keeps it
	}
	schedule := *g.ClientReset
	g.ClientReset = &schedule
	if *before.ClientReset != schedule {
		changed = append(changed, "client_reset_schedule")
	}
	if g.AllowFileLists == nil {
		g.AllowFileLists = before.AllowFileLists // likewise
	}
	allowFile := *g.AllowFileLists
	g.AllowFileLists = &allowFile
	if *before.AllowFileLists != allowFile {
		changed = append(changed, "allow_file_lists")
	}
	if g.LocalDNSReasonRequired == nil {
		g.LocalDNSReasonRequired = before.LocalDNSReasonRequired // likewise
	}
	reasonRequired := *g.LocalDNSReasonRequired
	g.LocalDNSReasonRequired = &reasonRequired
	if *before.LocalDNSReasonRequired != reasonRequired {
		changed = append(changed, "localdns_reason_required")
	}
	if g.LocalDNSExtraDomains == nil {
		g.LocalDNSExtraDomains = before.LocalDNSExtraDomains // likewise
	}
	extra, _ := localdns.CheckExtraDomains(*g.LocalDNSExtraDomains) // checked by Validate
	g.LocalDNSExtraDomains = &extra
	if !slices.Equal(*before.LocalDNSExtraDomains, extra) {
		changed = append(changed, "localdns_extra_domains")
	}
	if g.ScheduleGroupWindowMaxMinutes == nil {
		g.ScheduleGroupWindowMaxMinutes = before.ScheduleGroupWindowMaxMinutes // likewise
	}
	groupWindowMax := *g.ScheduleGroupWindowMaxMinutes
	g.ScheduleGroupWindowMaxMinutes = &groupWindowMax
	if *before.ScheduleGroupWindowMaxMinutes != groupWindowMax {
		changed = append(changed, "schedule_group_window_max_minutes")
	}
	if g.ClientTempMaxMinutes == nil {
		g.ClientTempMaxMinutes = before.ClientTempMaxMinutes // likewise
	}
	clientTempMax := *g.ClientTempMaxMinutes
	g.ClientTempMaxMinutes = &clientTempMax
	if *before.ClientTempMaxMinutes != clientTempMax {
		changed = append(changed, "client_temp_max_minutes")
	}
	if g.ClientTempReasonRequired == nil {
		g.ClientTempReasonRequired = before.ClientTempReasonRequired // likewise
	}
	clientTempReason := *g.ClientTempReasonRequired
	g.ClientTempReasonRequired = &clientTempReason
	if *before.ClientTempReasonRequired != clientTempReason {
		changed = append(changed, "client_temp_reason_required")
	}
	if len(changed) == 0 {
		return nil
	}
	now := s.now()
	err := s.do(ctx, a, func(t *txn) error {
		t.entry.Target = "settings:" + GeneralKey
		t.entry.Detail["changed"] = changed
		t.entry.Detail["session_lifetime_minutes"] = g.SessionLifetimeMinutes
		t.entry.Detail["idle_timeout_minutes"] = g.IdleTimeoutMinutes
		t.entry.Detail["audit_retention_days"] = g.AuditRetentionDays
		t.entry.Detail["client_reset_schedule"] = schedule
		t.entry.Detail["allow_file_lists"] = allowFile
		t.entry.Detail["localdns_reason_required"] = reasonRequired
		t.entry.Detail["localdns_extra_domains"] = extra
		t.entry.Detail["schedule_group_window_max_minutes"] = groupWindowMax
		t.entry.Detail["client_temp_max_minutes"] = clientTempMax
		t.entry.Detail["client_temp_reason_required"] = clientTempReason
		value, err := json.Marshal(g)
		if err != nil {
			return err
		}
		return t.q.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: GeneralKey, Value: string(value), UpdatedAt: store.Millis(now), UpdatedBy: a.Username,
		})
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.generalAt, s.generalBy = store.FromMillis(store.Millis(now)), a.Username
	s.retention = g.AuditRetentionDays
	s.schedule = schedule
	s.allowFile = allowFile
	s.reasonOptional = !reasonRequired
	s.extraDomains = extra
	s.groupWindowMax = groupWindowMax
	s.clientTempMax = clientTempMax
	s.clientTempReasonOptional = !clientTempReason
	if s.Sessions != nil {
		s.Sessions.SetLifetimes(g.durations())
	}
	s.mu.Unlock()
	if before.AuditRetentionDays != g.AuditRetentionDays && s.RetentionChanged != nil {
		s.RetentionChanged()
	}
	return nil
}
