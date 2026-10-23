// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Service makes every change to instances. Each change runs in one transaction that checks instances.manage,
// applies it and writes the audit row; the pool follows once it has committed. Connection tests run before the
// transaction, so a slow Pi-hole never holds the database's write lock.
//
// Refusals are *rbac.Error values whose Code is the API error code. A failed connection test is a *TestError.
type Service struct {
	Store *store.Store
	Audit *audit.Logger
	Pool  *Pool
	// Now returns the current time; nil means time.Now.
	Now func() time.Time
}

// Input is an instance's editable settings.
type Input struct {
	Name    string
	BaseURL string
	EnvName string
	TLSMode piholeapi.TLSMode // TLSVerify if empty
	CAFile  string
}

// TestError is a refused enable or edit: the connection test with the new settings failed. Err is the pool or
// Pi-hole error; Kind(Err) gives its code.
type TestError struct {
	Instance string // name
	EnvName  string // names the password variable
	Err      error
}

func (e *TestError) Error() string {
	return "the connection test for " + e.Instance + " failed: " + e.Err.Error()
}

func (e *TestError) Unwrap() error { return e.Err }

const (
	maxName    = 64
	maxEnvName = 64
	maxBaseURL = 2048
	maxCAFile  = 4096
)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func fromRow(r db.Instance) Instance {
	return Instance{
		ID: r.ID, Name: r.Name, BaseURL: r.BaseUrl, EnvName: r.EnvName,
		TLSMode: piholeapi.TLSMode(r.TlsMode), CAFile: r.CaFile.String, Enabled: r.Enabled,
		CreatedAt: store.FromMillis(r.CreatedAt),
	}
}

func instanceTarget(name string) string { return "instance:" + name }

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func notFound(id int64) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There is no instance with ID %d.", id),
		Details: map[string]any{"instance_id": id}}
}

// normalize checks the settings and returns them in canonical form: trimmed, the base URL canonical, the TLS mode
// set. A CA file must be readable and hold a certificate.
func (in Input) normalize() (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxName || hasControl(in.Name) {
		return in, validation("name", "An instance name is 1-%d characters, with no control characters.", maxName)
	}
	if len(in.BaseURL) > maxBaseURL {
		return in, validation("base_url", "The base URL is at most %d characters.", maxBaseURL)
	}
	base, err := piholeapi.ParseBaseURL(in.BaseURL)
	if err != nil {
		return in, validation("base_url", "The %s.", err)
	}
	in.BaseURL = base
	in.EnvName = strings.TrimSpace(in.EnvName)
	if !secrets.ValidEnvName(in.EnvName) || len(in.EnvName) > maxEnvName {
		return in, validation("env_name",
			"The env name is 1-%d characters of A-Z, 0-9 and _: the password is read from %s.", maxEnvName,
			secrets.InstanceVar("<env name>"))
	}
	switch in.TLSMode {
	case "":
		in.TLSMode = piholeapi.TLSVerify
	case piholeapi.TLSVerify, piholeapi.TLSInsecure:
	default:
		return in, validation("tls_mode", "The TLS mode is verify or insecure.")
	}
	in.CAFile = strings.TrimSpace(in.CAFile)
	if len(in.CAFile) > maxCAFile {
		return in, validation("ca_file", "The CA file path is at most %d characters.", maxCAFile)
	}
	if in.CAFile != "" {
		switch {
		case in.TLSMode != piholeapi.TLSVerify:
			return in, validation("ca_file", "A CA file can only be used with TLS mode verify.")
		case !strings.HasPrefix(in.BaseURL, "https://"):
			return in, validation("ca_file", "A CA file only applies to an https:// base URL.")
		case !filepath.IsAbs(in.CAFile):
			return in, validation("ca_file", "The CA file must be an absolute path.")
		}
		if err := piholeapi.CheckCAFile(in.CAFile); err != nil {
			return in, validation("ca_file", "The %s.", err)
		}
	}
	return in, nil
}

func hasControl(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	return strings.ContainsFunc(s, unicode.IsControl)
}

func (in Input) apply(inst Instance) Instance {
	inst.Name, inst.BaseURL, inst.EnvName, inst.TLSMode, inst.CAFile = in.Name, in.BaseURL, in.EnvName, in.TLSMode, in.CAFile
	return inst
}

// sameConnection reports whether two instances connect the same way: same base URL, TLS settings and password
// variable.
func (i Instance) sameConnection(o Instance) bool {
	return i.BaseURL == o.BaseURL && i.TLSMode == o.TLSMode && i.CAFile == o.CAFile && i.EnvName == o.EnvName
}

// LoadPool fills the pool from the database. serve calls it at startup.
func (s *Service) LoadPool(ctx context.Context) error {
	insts, err := s.List(ctx)
	if err != nil {
		return err
	}
	s.Pool.Load(insts)
	return nil
}

// List returns every instance, by name.
func (s *Service) List(ctx context.Context) ([]Instance, error) {
	rows, err := s.Store.Read().ListInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("instances: list: %w", err)
	}
	out := make([]Instance, len(rows))
	for i, r := range rows {
		out[i] = fromRow(r)
	}
	return out, nil
}

// Get returns one instance.
func (s *Service) Get(ctx context.Context, id int64) (Instance, error) {
	r, err := s.Store.Read().GetInstance(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, notFound(id)
	}
	if err != nil {
		return Instance{}, err
	}
	return fromRow(r), nil
}

// errNoChange ends a change that would leave everything as it is: nothing is written and nothing is audited.
var errNoChange = errors.New("no change")

type txn struct {
	ctx   context.Context
	q     *db.Queries
	set   *rbac.Set
	now   time.Time
	entry *audit.Entry
}

// do runs fn as one audited change, as rbac.Manager does: a refusal for a missing permission is audited as
// permission_denied, and the AUDIT line is written after the commit.
func (s *Service) do(ctx context.Context, a rbac.Actor, action string, fn func(t *txn) error) error {
	now := s.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: action, IP: a.IP, Detail: map[string]any{}}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := rbac.Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		if err := fn(&txn{ctx: ctx, q: q, set: set, now: now, entry: &entry}); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case errors.Is(err, errNoChange):
		return nil
	case rbac.IsCode(err, rbac.CodeForbidden):
		e, _ := rbac.AsError(err)
		detail := map[string]any{"attempted": action}
		for k, v := range e.Details {
			detail[k] = v
		}
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: entry.Target, Err: err, Detail: detail, IP: a.IP,
		}
		if rerr := s.Audit.Record(ctx, s.Store, denied); rerr != nil {
			return fmt.Errorf("audit refusal: %w", rerr)
		}
		return err
	case err != nil:
		return err
	}
	s.Audit.Log(entry)
	return nil
}

func (t *txn) require() error {
	if t.set.CanGlobal(rbac.InstancesManage) {
		return nil
	}
	return rbac.Forbidden(rbac.InstancesManage)
}

// load reads an instance and makes it the audit target.
func (t *txn) load(id int64) (Instance, error) {
	r, err := t.q.GetInstance(t.ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, notFound(id)
	}
	if err != nil {
		return Instance{}, err
	}
	inst := fromRow(r)
	t.entry.Target = instanceTarget(inst.Name)
	t.entry.InstanceID, t.entry.InstanceName = inst.ID, inst.Name
	return inst, nil
}

// checkUnique refuses a name (compared case-insensitively) or env name that another instance already has. The
// UNIQUE constraints back this up.
func (t *txn) checkUnique(in Input, self int64) error {
	rows, err := t.q.ListInstances(t.ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		switch {
		case r.ID == self:
		case strings.EqualFold(r.Name, in.Name):
			return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("There is already an instance called %q.", r.Name),
				Details: map[string]any{"field": "name"}}
		case r.EnvName == in.EnvName:
			return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("Instance %q already uses the env name %s.", r.Name, r.EnvName),
				Details: map[string]any{"field": "env_name"}}
		}
	}
	return nil
}

func uniqueBackstop(err error) error {
	if store.Constraint(err) == store.Unique {
		return &rbac.Error{Code: rbac.CodeConflict, Message: "Another instance already uses that name or env name."}
	}
	return err
}

func caFile(path string) sql.NullString { return sql.NullString{String: path, Valid: path != ""} }

// precheck refuses, with the usual audit, an actor who can't manage instances or an instance that doesn't exist,
// before any connection test is made on their behalf. It writes nothing.
func (s *Service) precheck(ctx context.Context, a rbac.Actor, action string, id int64) error {
	return s.do(ctx, a, action, func(t *txn) error {
		if _, err := t.load(id); err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		return errNoChange
	})
}

// test runs the connection test and, if it fails, records the refusal of action and returns a *TestError. The audit
// detail has the error code only: the full error can name internal addresses.
func (s *Service) test(ctx context.Context, a rbac.Actor, action string, inst Instance) error {
	err := s.Pool.Test(ctx, inst)
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	code := Kind(err)
	entry := audit.Entry{
		At: s.now(), UserID: a.UserID, Username: a.Username, Action: action, Target: instanceTarget(inst.Name),
		InstanceID: inst.ID, InstanceName: inst.Name, IP: a.IP,
		Err: fmt.Errorf("connection test failed: %s", code), Detail: map[string]any{"instance_id": inst.ID},
	}
	if rerr := s.Audit.Record(ctx, s.Store, entry); rerr != nil {
		return fmt.Errorf("audit refusal: %w", rerr)
	}
	return &TestError{Instance: inst.Name, EnvName: inst.EnvName, Err: err}
}

// changed reports which connection-affecting settings will change, for the audit detail. A rename isn't listed.
func changed(before, after Instance) []string {
	var out []string
	if before.BaseURL != after.BaseURL {
		out = append(out, "base_url")
	}
	if before.EnvName != after.EnvName {
		out = append(out, "env_name")
	}
	if before.TLSMode != after.TLSMode {
		out = append(out, "tls_mode")
	}
	if before.CAFile != after.CAFile {
		out = append(out, "ca_file")
	}
	return out
}

// Create adds an instance. New instances are disabled: enabling one needs its password variable and a successful
// connection test (SetEnabled).
func (s *Service) Create(ctx context.Context, a rbac.Actor, in Input) (Instance, error) {
	var inst Instance
	err := s.do(ctx, a, audit.ActionInstanceCreate, func(t *txn) error {
		in, err := in.normalize()
		if err != nil {
			return err
		}
		t.entry.Target = instanceTarget(in.Name)
		if err := t.require(); err != nil {
			return err
		}
		if err := t.checkUnique(in, 0); err != nil {
			return err
		}
		id, err := t.q.CreateInstance(t.ctx, db.CreateInstanceParams{
			Name: in.Name, BaseUrl: in.BaseURL, EnvName: in.EnvName, TlsMode: string(in.TLSMode),
			CaFile: caFile(in.CAFile), CreatedAt: store.Millis(t.now),
		})
		if err != nil {
			return uniqueBackstop(err)
		}
		inst = in.apply(Instance{ID: id, CreatedAt: store.FromMillis(store.Millis(t.now))})
		t.entry.InstanceID, t.entry.InstanceName = id, in.Name
		t.entry.Detail["instance_id"] = id
		t.entry.Detail["base_url"] = in.BaseURL
		t.entry.Detail["env_name"] = in.EnvName
		t.entry.Detail["tls_mode"] = in.TLSMode
		if in.CAFile != "" {
			t.entry.Detail["ca_file"] = in.CAFile
		}
		return nil
	})
	return inst, err
}

// Update changes an instance's settings. If the instance is enabled and the change affects how it connects, the new
// settings must pass a connection test first; to save settings that don't work yet, disable the instance first.
func (s *Service) Update(ctx context.Context, a rbac.Actor, id int64, in Input) (Instance, error) {
	if err := s.precheck(ctx, a, audit.ActionInstanceUpdate, id); err != nil {
		return Instance{}, err
	}
	before, err := s.Get(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	norm, err := in.normalize()
	if err != nil {
		return Instance{}, err
	}
	after := norm.apply(before)
	if before.Enabled && !before.sameConnection(after) {
		if err := s.test(ctx, a, audit.ActionInstanceUpdate, after); err != nil {
			return Instance{}, err
		}
	}

	err = s.do(ctx, a, audit.ActionInstanceUpdate, func(t *txn) error {
		cur, err := t.load(id)
		if err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		// The tested settings only count if nothing changed while the test ran.
		if cur != before {
			return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("%s was changed while it was being tested. Try again.", cur.Name)}
		}
		if after == cur {
			return errNoChange
		}
		if err := t.checkUnique(norm, id); err != nil {
			return err
		}
		err = t.q.UpdateInstance(t.ctx, db.UpdateInstanceParams{
			Name: after.Name, BaseUrl: after.BaseURL, EnvName: after.EnvName, TlsMode: string(after.TLSMode),
			CaFile: caFile(after.CAFile), ID: id,
		})
		if err != nil {
			return uniqueBackstop(err)
		}
		t.entry.Target, t.entry.InstanceName = instanceTarget(after.Name), after.Name
		t.entry.Detail["instance_id"] = id
		if after.Name != cur.Name {
			t.entry.Detail["renamed_from"] = cur.Name
		}
		if c := changed(cur, after); len(c) > 0 {
			t.entry.Detail["changed"] = c
		}
		return nil
	})
	if err != nil {
		return Instance{}, err
	}
	if after.Enabled {
		s.Pool.Put(after)
	}
	return after, nil
}

// SetEnabled enables or disables an instance. Enabling runs a connection test with the stored settings and is
// refused if it fails.
func (s *Service) SetEnabled(ctx context.Context, a rbac.Actor, id int64, enabled bool) (Instance, error) {
	action := audit.ActionInstanceDisable
	if enabled {
		action = audit.ActionInstanceEnable
	}
	if err := s.precheck(ctx, a, action, id); err != nil {
		return Instance{}, err
	}
	before, err := s.Get(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if before.Enabled == enabled {
		return before, nil
	}
	if enabled {
		if err := s.test(ctx, a, action, before); err != nil {
			return Instance{}, err
		}
	}

	var inst Instance
	err = s.do(ctx, a, action, func(t *txn) error {
		cur, err := t.load(id)
		if err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		inst = cur
		if cur.Enabled == enabled {
			return errNoChange
		}
		if enabled && !cur.sameConnection(before) {
			return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("%s was changed while it was being tested. Try again.", cur.Name)}
		}
		if err := t.q.SetInstanceEnabled(t.ctx, db.SetInstanceEnabledParams{Enabled: enabled, ID: id}); err != nil {
			return err
		}
		inst.Enabled = enabled
		t.entry.Detail["instance_id"] = id
		return nil
	})
	if err != nil {
		return Instance{}, err
	}
	s.Pool.Put(inst) // removes it when disabled
	return inst, nil
}

// Delete removes an instance. It is refused while a role grant, an instance group or a client-reset target refers
// to it, with a message that lists them.
func (s *Service) Delete(ctx context.Context, a rbac.Actor, id int64) error {
	err := s.do(ctx, a, audit.ActionInstanceDelete, func(t *txn) error {
		inst, err := t.load(id)
		if err != nil {
			return err
		}
		if err := t.require(); err != nil {
			return err
		}
		if err := t.checkUnused(inst); err != nil {
			return err
		}
		if err := t.q.DeleteInstance(t.ctx, id); err != nil {
			if store.Constraint(err) == store.ForeignKey {
				return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf("%s is still in use.", inst.Name)}
			}
			return err
		}
		// The audit row can't reference the deleted row; the name is kept.
		t.entry.InstanceID = 0
		t.entry.Detail["instance_id"] = id
		return nil
	})
	if err != nil {
		return err
	}
	s.Pool.Remove(id)
	return nil
}

func (t *txn) checkUnused(inst Instance) error {
	ref := sql.NullInt64{Int64: inst.ID, Valid: true}
	roles, err := t.q.ListRolesWithGrantsOnInstance(t.ctx, ref)
	if err != nil {
		return err
	}
	groups, err := t.q.ListGroupsWithInstance(t.ctx, inst.ID)
	if err != nil {
		return err
	}
	resets, err := t.q.CountClientResetTargetsForInstance(t.ctx, ref)
	if err != nil {
		return err
	}
	var uses []string
	if len(roles) > 0 {
		uses = append(uses, plural(len(roles), "role")+" "+quoteJoin(roles))
	}
	if len(groups) > 0 {
		uses = append(uses, plural(len(groups), "group")+" "+quoteJoin(groups))
	}
	if resets > 0 {
		uses = append(uses, plural(int(resets), "client reset target"))
	}
	if len(uses) == 0 {
		return nil
	}
	return &rbac.Error{
		Code:    rbac.CodeConflict,
		Message: fmt.Sprintf("%s is still used by %s. Remove it from them first.", inst.Name, strings.Join(uses, "; ")),
		Details: map[string]any{"roles": roles, "groups": groups, "client_reset_targets": resets},
	}
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func quoteJoin(names []string) string {
	q := slices.Clone(names)
	for i, n := range q {
		q[i] = fmt.Sprintf("%q", n)
	}
	return strings.Join(q, ", ")
}

// Test runs the connection test against an instance's stored settings, without changing anything. It isn't audited.
func (s *Service) Test(ctx context.Context, a rbac.Actor, id int64) error {
	if err := s.precheck(ctx, a, audit.ActionInstanceTest, id); err != nil {
		return err
	}
	inst, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.Pool.Test(ctx, inst)
}
