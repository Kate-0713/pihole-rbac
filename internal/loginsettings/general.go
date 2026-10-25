// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginsettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// GeneralKey is the settings row holding the general settings.
const GeneralKey = "general"

// General are the general settings: how long sessions last, and how long audit rows are kept.
type General struct {
	SessionLifetimeMinutes int `json:"session_lifetime_minutes"` // absolute, from login
	IdleTimeoutMinutes     int `json:"idle_timeout_minutes"`     // since the last request
	// AuditRetentionDays is how long audit rows are kept. Rows saved before the setting existed have none, which loads
	// as the default.
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
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
	return nil
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
	if s.Sessions != nil {
		s.Sessions.SetLifetimes(g.durations())
	}
	return nil
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
	return GeneralView{
		General: General{
			SessionLifetimeMinutes: int(lifetime / time.Minute), IdleTimeoutMinutes: int(idle / time.Minute),
			AuditRetentionDays: retention,
		},
		UpdatedAt: s.generalAt, UpdatedBy: s.generalBy,
	}
}

// SaveGeneral saves the general settings and applies them: a new lifetime to sessions started from now on, a new
// idle timeout to every session at once, and a new audit retention at the next prune, which RetentionChanged brings
// forward. It needs settings.manage, and is audited as settings_update.
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
	if s.Sessions != nil {
		s.Sessions.SetLifetimes(g.durations())
	}
	s.mu.Unlock()
	if before.AuditRetentionDays != g.AuditRetentionDays && s.RetentionChanged != nil {
		s.RetentionChanged()
	}
	return nil
}
