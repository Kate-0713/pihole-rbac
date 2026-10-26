// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1import

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// ErrNotFresh is returned by Apply for a database that already has something in it.
var ErrNotFresh = errors.New("not a fresh database")

// Via is put in the detail of every audit row the import writes, so they can be told apart from changes made in the
// app.
const Via = "import-json"

// Result says what Apply created.
type Result struct {
	InstanceID  int64
	SetupClosed bool
	Entries     int // audit rows written
}

// Apply writes the plan into a fresh database in one transaction: either everything is imported or nothing is. A
// fresh database is one where first-run setup is still open and there are no users, instances, channels or roles
// other than the builtin admin, so an import can't be run twice or mixed with settings made in the app. Each thing
// created gets the audit row the app would write for it, by user, with Via in its detail. If the plan has a local
// admin, setup is closed, as reset-admin closes it.
//
// Secrets are sealed with c, which must be the master key the plan was built with (nil if there was none).
func Apply(ctx context.Context, st *store.Store, al *audit.Logger, c *secrets.Cipher, p *Plan, by string, now time.Time) (Result, error) {
	if len(p.Errors) > 0 {
		return Result{}, fmt.Errorf("the plan has %d %s to fix first", len(p.Errors), plural(len(p.Errors), "problem"))
	}
	if !p.Checked && p.Offline == "" {
		return Result{}, errors.New("the plan hasn't been checked")
	}
	if (p.Instance.Store || slices.ContainsFunc(p.Channels, func(c PlannedChannel) bool { return c.Store }) ||
		(p.LDAP != nil && p.LDAP.Store)) && c == nil {
		return Result{}, errors.New("the plan stores secrets, but no master key was given")
	}
	a := &applier{ctx: ctx, by: by, now: now, c: c, p: p}
	err := st.WithTx(ctx, func(q *db.Queries) error {
		a.q = q
		return a.run()
	})
	if err != nil {
		return Result{}, err
	}
	for _, e := range a.entries {
		al.Log(e)
	}
	return Result{InstanceID: a.instanceID, SetupClosed: a.closed, Entries: len(a.entries)}, nil
}

type applier struct {
	ctx context.Context
	q   *db.Queries
	by  string
	now time.Time
	c   *secrets.Cipher
	p   *Plan

	instanceID int64
	roleIDs    map[string]int64 // v1 role name to role ID
	closed     bool
	entries    []audit.Entry
}

// record inserts an audit row and keeps it, to be logged once the transaction commits.
func (a *applier) record(e audit.Entry) error {
	e.At, e.Username = a.now, a.by
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	e.Detail["via"] = Via
	if _, err := audit.Insert(a.ctx, a.q, e); err != nil {
		return err
	}
	a.entries = append(a.entries, e)
	return nil
}

func (a *applier) run() error {
	if err := a.checkFresh(); err != nil {
		return err
	}
	steps := []func() error{a.instance, a.roles, a.users, a.ldap, a.mappings, a.methods, a.schedule, a.channels, a.protected,
		a.rules, a.closeSetup}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (a *applier) checkFresh() error { return Fresh(a.ctx, a.q) }

// Fresh reports whether the database is one import-json can import into: first-run setup still open, and no users,
// instances, channels or roles besides the builtin admin. Otherwise the error, wrapping ErrNotFresh, says what is
// there.
func Fresh(ctx context.Context, q *db.Queries) error {
	state, err := q.GetSetupState(ctx)
	if err != nil {
		return err
	}
	var found []string
	if state.CompletedAt.Valid {
		found = append(found, "first-run setup is complete")
	}
	users, err := q.ListUsers(ctx)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		found = append(found, fmt.Sprintf("%d %s", len(users), plural(len(users), "user")))
	}
	insts, err := q.ListInstances(ctx)
	if err != nil {
		return err
	}
	if len(insts) > 0 {
		found = append(found, fmt.Sprintf("%d %s", len(insts), plural(len(insts), "instance")))
	}
	chans, err := q.ListChannels(ctx)
	if err != nil {
		return err
	}
	if len(chans) > 0 {
		found = append(found, fmt.Sprintf("%d notification %s", len(chans), plural(len(chans), "channel")))
	}
	roles, err := q.ListRoles(ctx)
	if err != nil {
		return err
	}
	if n := len(roles) - 1; n > 0 {
		found = append(found, fmt.Sprintf("%d %s besides admin", n, plural(n, "role")))
	}
	if len(found) > 0 {
		return fmt.Errorf("%w: %s. import-json only imports into a new database: point PIHOLE_RBAC_DATA_DIR at an empty directory", ErrNotFresh, strings.Join(found, ", "))
	}
	return nil
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func (a *applier) sealed(v secrets.Value, aad []byte) (secrets.Sealed, error) {
	return a.c.Seal(v, aad)
}

func (a *applier) instance() error {
	pi := a.p.Instance
	in := pi.Input
	id, err := a.q.CreateInstance(a.ctx, db.CreateInstanceParams{
		Name: in.Name, BaseUrl: in.BaseURL, EnvName: nullString(in.EnvName), TlsMode: string(in.TLSMode),
		CaFile: nullString(in.CAFile), CreatedAt: store.Millis(a.now),
	})
	if err != nil {
		return fmt.Errorf("create instance: %w", err)
	}
	a.instanceID = id
	detail := map[string]any{"instance_id": id, "base_url": in.BaseURL, "tls_mode": in.TLSMode, "enabled": pi.Enable}
	if in.EnvName != "" {
		detail["env_name"] = in.EnvName
	}
	if pi.Store && !pi.Password.IsZero() {
		s, err := a.sealed(pi.Password, secrets.AAD("instances", id))
		if err != nil {
			return err
		}
		if err := a.q.SetInstancePassword(a.ctx, db.SetInstancePasswordParams{
			PasswordCiphertext: s.Ciphertext, PasswordNonce: s.Nonce,
			PasswordKeyID:     sql.NullString{String: s.KeyID, Valid: true},
			PasswordUpdatedAt: sql.NullInt64{Int64: store.Millis(a.now), Valid: true},
			PasswordUpdatedBy: sql.NullString{String: a.by, Valid: true},
			ID:                id,
		}); err != nil {
			return err
		}
		detail["password"] = "stored"
	}
	if pi.Enable {
		if err := a.q.SetInstanceEnabled(a.ctx, db.SetInstanceEnabledParams{Enabled: true, ID: id}); err != nil {
			return err
		}
	}
	return a.record(audit.Entry{Action: audit.ActionInstanceCreate, Target: "instance:" + in.Name, InstanceID: id,
		InstanceName: in.Name, Detail: detail})
}

func (a *applier) roles() error {
	admin, err := a.q.GetBuiltinRole(a.ctx)
	if err != nil {
		return fmt.Errorf("builtin admin role: %w", err)
	}
	a.roleIDs = map[string]int64{v1Admin: admin.ID}
	for _, r := range a.p.Roles {
		id, err := a.q.CreateRole(a.ctx, db.CreateRoleParams{Name: r.Name, Description: r.Description, CreatedAt: store.Millis(a.now)})
		if err != nil {
			return fmt.Errorf("create role %s: %w", r.Name, err)
		}
		grants := []string{}
		for _, perm := range r.Permissions {
			if err := a.q.AddRoleGrantAll(a.ctx, db.AddRoleGrantAllParams{RoleID: id, Permission: perm}); err != nil {
				return fmt.Errorf("grant %s to %s: %w", perm, r.Name, err)
			}
			grants = append(grants, perm+" on all")
		}
		a.roleIDs[r.Name] = id
		if err := a.record(audit.Entry{Action: audit.ActionRoleCreate, Target: "role:" + r.Name,
			Detail: map[string]any{"role_id": id, "grants": grants}}); err != nil {
			return err
		}
	}
	return nil
}

func (a *applier) users() error {
	for _, u := range a.p.Users {
		row, err := a.q.CreateLocalUser(a.ctx, db.CreateLocalUserParams{
			Username: u.Username, PasswordHash: sql.NullString{String: u.Hash, Valid: true}, CreatedAt: store.Millis(a.now),
		})
		if err != nil {
			return fmt.Errorf("create user %s: %w", u.Username, err)
		}
		ids := []int64{}
		for _, r := range u.Roles {
			id := a.roleIDs[r]
			if err := a.q.AddUserRole(a.ctx, db.AddUserRoleParams{UserID: row.ID, RoleID: id}); err != nil {
				return fmt.Errorf("give %s the %s role: %w", u.Username, r, err)
			}
			ids = append(ids, id)
		}
		if err := a.record(audit.Entry{Action: audit.ActionUserCreate, Target: "user:" + u.Username,
			Detail: map[string]any{"user_id": row.ID, "roles": ids, "password": "v1 hash"}}); err != nil {
			return err
		}
	}
	return nil
}

func (a *applier) ldap() error {
	l := a.p.LDAP
	if l == nil {
		return nil
	}
	value, err := json.Marshal(l.Settings)
	if err != nil {
		return err
	}
	if err := a.q.UpsertSetting(a.ctx, db.UpsertSettingParams{
		Key: auth.LDAPSettingsKey, Value: string(value), UpdatedAt: store.Millis(a.now), UpdatedBy: a.by,
	}); err != nil {
		return err
	}
	detail := map[string]any{"changed": []string{"url", "bind_dn", "base_dn", "user_filter", "tls_mode", "allow_cn_fallback"}}
	if l.Store && !l.Password.IsZero() {
		s, err := a.sealed(l.Password, loginsettings.BindPasswordAAD)
		if err != nil {
			return err
		}
		if _, err := a.q.SetSettingSecret(a.ctx, db.SetSettingSecretParams{
			SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce,
			SecretKeyID:     sql.NullString{String: s.KeyID, Valid: true},
			SecretUpdatedAt: sql.NullInt64{Int64: store.Millis(a.now), Valid: true},
			SecretUpdatedBy: sql.NullString{String: a.by, Valid: true},
			Key:             auth.LDAPSettingsKey,
		}); err != nil {
			return err
		}
		detail["bind_password"] = "stored"
	}
	return a.record(audit.Entry{Action: audit.ActionSettingsUpdate, Target: "settings:" + auth.LDAPSettingsKey, Detail: detail})
}

func (a *applier) mappings() error {
	if a.p.LDAP == nil {
		return nil
	}
	for _, m := range a.p.Mappings {
		id, err := a.q.CreateLDAPMapping(a.ctx, db.CreateLDAPMappingParams{
			RoleID: a.roleIDs[m.Role], GroupDn: m.DN, GroupDnNorm: m.Norm, CreatedAt: store.Millis(a.now),
		})
		if err != nil {
			return fmt.Errorf("map %s to %s: %w", m.DN, m.Role, err)
		}
		if err := a.record(audit.Entry{Action: audit.ActionLDAPMappingAdd, Target: "role:" + m.Role,
			Detail: map[string]any{"mapping_id": id, "group_dn": m.DN}}); err != nil {
			return err
		}
	}
	return nil
}

func (a *applier) methods() error {
	methods := a.p.Methods
	if len(methods) == 0 || slices.Equal(methods, auth.DefaultSettings().Methods) {
		return nil // the default needs no row
	}
	if err := auth.ValidateMethods(methods); err != nil {
		return err
	}
	if slices.Contains(methods, auth.MethodLDAP) && (a.p.LDAP == nil || !a.p.LDAP.Enable) {
		return errors.New("LDAP login can't be turned on without a passing bind test") // Check keeps this from happening
	}
	value, err := json.Marshal(auth.Settings{Methods: methods})
	if err != nil {
		return err
	}
	if err := a.q.UpsertSetting(a.ctx, db.UpsertSettingParams{
		Key: auth.SettingsKey, Value: string(value), UpdatedAt: store.Millis(a.now), UpdatedBy: a.by,
	}); err != nil {
		return err
	}
	return a.record(audit.Entry{Action: audit.ActionSettingsUpdate, Target: "settings:" + auth.SettingsKey,
		Detail: map[string]any{"changed": []string{"methods"}, "methods": methods, "previous_methods": auth.DefaultSettings().Methods}})
}

func (a *applier) schedule() error {
	s := a.p.Schedule
	if s == nil {
		return nil
	}
	g := loginsettings.General{
		SessionLifetimeMinutes: int(auth.DefaultLifetime / time.Minute),
		IdleTimeoutMinutes:     int(auth.DefaultIdleTimeout / time.Minute),
		AuditRetentionDays:     loginsettings.DefaultRetentionDays,
		ClientReset:            s,
	}
	if err := g.Validate(); err != nil {
		return err
	}
	value, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if err := a.q.UpsertSetting(a.ctx, db.UpsertSettingParams{
		Key: loginsettings.GeneralKey, Value: string(value), UpdatedAt: store.Millis(a.now), UpdatedBy: a.by,
	}); err != nil {
		return err
	}
	return a.record(audit.Entry{Action: audit.ActionSettingsUpdate, Target: "settings:" + loginsettings.GeneralKey,
		Detail: map[string]any{"changed": []string{"client_reset_schedule"}, "client_reset_schedule": *s}})
}

func (a *applier) channels() error {
	for _, ch := range a.p.Channels {
		in := ch.Input
		cfg, err := notifications.ConfigJSON(in)
		if err != nil {
			return err
		}
		id, err := a.q.CreateChannel(a.ctx, db.CreateChannelParams{
			Kind: string(in.Kind), Name: in.Name, EnvName: nullString(in.EnvName), Config: cfg, Enabled: in.Enabled,
			CreatedAt: store.Millis(a.now),
		})
		if err != nil {
			return fmt.Errorf("create channel %s: %w", in.Name, err)
		}
		detail := map[string]any{"channel_id": id}
		in.AuditDetail(detail)
		if ch.Store {
			s, err := a.sealed(*in.Secret, secrets.AAD("notification_channels", id))
			if err != nil {
				return err
			}
			if err := a.q.SetChannelSecret(a.ctx, db.SetChannelSecretParams{
				SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce,
				SecretKeyID:     sql.NullString{String: s.KeyID, Valid: true},
				SecretUpdatedAt: sql.NullInt64{Int64: store.Millis(a.now), Valid: true},
				SecretUpdatedBy: sql.NullString{String: a.by, Valid: true},
				ID:              id,
			}); err != nil {
				return err
			}
			detail["secret"] = "stored"
		}
		for _, e := range in.Events {
			if err := a.q.AddChannelRule(a.ctx, db.AddChannelRuleParams{ChannelID: id, Event: e}); err != nil {
				return err
			}
		}
		if err := a.record(audit.Entry{Action: audit.ActionChannelCreate, Target: "channel:" + in.Name, Detail: detail}); err != nil {
			return err
		}
	}
	return nil
}

func (a *applier) protected() error {
	if len(a.p.Protected) == 0 {
		return nil
	}
	for _, g := range a.p.Protected {
		if err := a.q.AddProtectedGroup(a.ctx, db.AddProtectedGroupParams{
			InstanceID: sql.NullInt64{Int64: a.instanceID, Valid: true}, PiholeGroup: g,
		}); err != nil {
			return fmt.Errorf("protected group %s: %w", g, err)
		}
	}
	name := a.p.Instance.Input.Name
	added := make([]string, len(a.p.Protected))
	for i, g := range a.p.Protected {
		added[i] = g + " on " + name
	}
	return a.record(audit.Entry{Action: audit.ActionProtectedGroups, Target: "notifications:protected_groups",
		Detail: map[string]any{"added": added}})
}

func (a *applier) rules() error {
	if len(a.p.Rules) == 0 {
		return nil
	}
	name := a.p.Instance.Input.Name
	var added []string
	for _, r := range a.p.Rules {
		groups, err := json.Marshal(r.Groups)
		if err != nil {
			return err
		}
		if err := a.q.AddClientResetRule(a.ctx, db.AddClientResetRuleParams{
			InstanceID: sql.NullInt64{Int64: a.instanceID, Valid: true}, CommentPrefix: r.Prefix,
			GroupMatch: string(r.Match), TargetGroups: string(groups),
		}); err != nil {
			return fmt.Errorf("client reset rule %s: %w", r.Prefix, err)
		}
		added = append(added, clientreset.Describe(r.Prefix, r.Match, r.Groups, name))
	}
	slices.Sort(added)
	return a.record(audit.Entry{Action: audit.ActionClientResetRules, Target: "client_reset:rules", Detail: map[string]any{"added": added}})
}

// closeSetup closes first-run setup when an enabled local admin was imported, as reset-admin does. Otherwise it stays
// open, and the admin is created through setup as usual.
func (a *applier) closeSetup() error {
	n, err := a.q.CountEnabledLocalAdmins(a.ctx)
	if err != nil || n == 0 {
		return err
	}
	closed, err := a.q.CompleteSetup(a.ctx, sql.NullInt64{Int64: store.Millis(a.now), Valid: true})
	if err != nil {
		return err
	}
	a.closed = closed == 1
	if !a.closed {
		return nil
	}
	return a.record(audit.Entry{Action: audit.ActionSetup, Target: "setup", Detail: map[string]any{"local_admins": n}})
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
