// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loginsettings owns how people log in: the enabled login methods, the LDAP connection settings and the LDAP
// bind password, and the authenticator built from them; and the general settings, which for now are how long
// sessions last. Saving any of them rebuilds the login chain and the
// directory the session recheck uses, without a restart.
//
// The bind password is a tier 2 secret: stored encrypted on the ldap settings row, with
// PIHOLE_RBAC_LDAP_BIND_PASSWORD as an optional override. It is only sent to an LDAP server someone confirmed it
// for: changing the server's address or how it is trusted needs the password entered again (the confirmation rule).
package loginsettings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Secrets is what the service needs from the secrets manager.
type Secrets interface {
	LDAPBindPassword() (secrets.Value, bool) // the environment override
	Cipher() *secrets.Cipher                 // nil without a master key
}

// Service holds the current login settings and the authenticator built from them. Load it once at startup.
type Service struct {
	Store   *store.Store
	Audit   *audit.Logger
	Secrets Secrets
	CAFile  string // PIHOLE_RBAC_LDAP_CA_FILE
	Logger  *slog.Logger
	Now     func() time.Time
	// Sessions takes the session lifetimes from the general settings; nil in tests that don't need them.
	Sessions SessionLifetimes

	auth *auth.SwappableAuthenticator

	saveMu sync.Mutex // one save at a time, from its test to its commit

	mu        sync.RWMutex
	methods   []auth.Method
	ldap      *auth.LDAPSettings // nil until saved
	ldapAt    time.Time          // when the LDAP settings were last saved, and by whom
	ldapBy    string
	stored    StoredPassword
	directory *auth.LDAPAuthenticator // built from the saved LDAP settings, enabled or not; nil without them
	generalAt time.Time               // when the general settings were last saved, and by whom
	generalBy string
}

// StoredPassword is the bind password as kept in the database.
type StoredPassword struct {
	Sealed    secrets.Sealed
	UpdatedAt time.Time
	UpdatedBy string
}

func (p StoredPassword) IsZero() bool { return len(p.Sealed.Ciphertext) == 0 }

// PasswordSource says where the bind password comes from.
type PasswordSource string

const (
	SourceEnvironment PasswordSource = "environment"
	SourceStored      PasswordSource = "stored"
	SourceNone        PasswordSource = "none"
)

var passwordAAD = secrets.AADKey("settings", auth.LDAPSettingsKey)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Load reads the settings, applies the session lifetimes and builds the login chain. A saved value that doesn't validate, or LDAP login enabled
// without LDAP settings, stops startup rather than silently changing who can log in.
func (s *Service) Load(ctx context.Context) error {
	q := s.Store.Read()
	settings, err := auth.LoadSettings(ctx, q)
	if err != nil {
		return err
	}
	if err := s.loadGeneral(ctx, q); err != nil {
		return err
	}
	ls, found, err := auth.LoadLDAPSettings(ctx, q)
	if err != nil {
		return err
	}
	var stored StoredPassword
	var at time.Time
	var by string
	if found {
		row, err := q.GetSetting(ctx, auth.LDAPSettingsKey)
		if err != nil {
			return err
		}
		stored = storedFromRow(row)
		at, by = store.FromMillis(row.UpdatedAt), row.UpdatedBy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.methods = settings.Methods
	if found {
		s.ldap, s.ldapAt, s.ldapBy = &ls, at, by
	}
	s.stored = stored
	if err := s.rebuildLocked(); err != nil {
		return err
	}
	if slices.Contains(s.methods, auth.MethodLDAP) {
		if strings.HasPrefix(ls.URL, "ldap://") {
			s.logger().Warn("LDAP uses ldap:// without TLS: passwords cross the network in the clear", "url", ls.URL)
		}
		if s.passwordSourceLocked() == SourceNone {
			s.logger().Warn("LDAP login is enabled but no bind password is set; LDAP logins will fail")
		}
	}
	return nil
}

func storedFromRow(row db.Setting) StoredPassword {
	if len(row.SecretCiphertext) == 0 {
		return StoredPassword{}
	}
	return StoredPassword{
		Sealed:    secrets.Sealed{KeyID: row.SecretKeyID.String, Nonce: row.SecretNonce, Ciphertext: row.SecretCiphertext},
		UpdatedAt: store.FromMillis(row.SecretUpdatedAt.Int64),
		UpdatedBy: row.SecretUpdatedBy.String,
	}
}

// rebuildLocked builds the directory from the saved LDAP settings and the login chain from the enabled methods, and
// swaps them in. Callers hold s.mu.
func (s *Service) rebuildLocked() error {
	var dir *auth.LDAPAuthenticator
	if s.ldap != nil {
		var err error
		dir, err = auth.NewLDAPAuthenticator(*s.ldap, s.bindPassword, s.CAFile)
		if err != nil {
			return fmt.Errorf("LDAP: %w", err)
		}
	}
	available := map[auth.Method]auth.Authenticator{auth.MethodLocal: auth.NewLocalAuthenticator(auth.StoreUsers{St: s.Store})}
	if dir != nil {
		available[auth.MethodLDAP] = dir
	}
	if slices.Contains(s.methods, auth.MethodLDAP) && dir == nil {
		return errors.New("LDAP login is enabled but no LDAP settings have been saved")
	}
	chain, err := auth.Build(s.methods, available)
	if err != nil {
		return fmt.Errorf("login methods: %w", err)
	}
	s.directory = dir
	if s.auth == nil {
		s.auth = auth.NewSwappable(chain)
	} else {
		s.auth.Set(chain)
	}
	return nil
}

// Authenticator is the login chain. It stays the same value; saving settings swaps what is inside it.
func (s *Service) Authenticator() auth.Authenticator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auth
}

// Directory is what the session recheck asks about logged-in LDAP users: nil unless LDAP login is enabled.
func (s *Service) Directory() auth.Directory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.directory == nil || !slices.Contains(s.methods, auth.MethodLDAP) {
		return nil
	}
	return s.directory
}

// bindPassword is asked on every LDAP login: the environment override if set, otherwise the stored password,
// decrypted with the current master key (so a reloaded key applies at once).
func (s *Service) bindPassword() (secrets.Value, bool) {
	if v, ok := s.Secrets.LDAPBindPassword(); ok {
		return v, true
	}
	s.mu.RLock()
	stored := s.stored
	s.mu.RUnlock()
	if stored.IsZero() {
		return secrets.Value{}, false
	}
	c := s.Secrets.Cipher()
	if c == nil {
		return secrets.Value{}, false
	}
	v, err := c.Open(stored.Sealed, passwordAAD)
	if err != nil {
		s.logger().Error("the stored LDAP bind password can't be decrypted", "err", err)
		return secrets.Value{}, false
	}
	return v, true
}

func (s *Service) passwordSourceLocked() PasswordSource {
	if _, ok := s.Secrets.LDAPBindPassword(); ok {
		return SourceEnvironment
	}
	if !s.stored.IsZero() {
		return SourceStored
	}
	return SourceNone
}

// LDAPView is the LDAP settings as the settings page shows them. Settings is nil until they are saved. The bind
// password is never part of it, only where it comes from and who stored it when.
type LDAPView struct {
	Settings         *auth.LDAPSettings
	UpdatedAt        time.Time
	UpdatedBy        string
	Enabled          bool // LDAP is among the login methods
	PasswordSource   PasswordSource
	PasswordUpdated  time.Time // for a stored password
	PasswordBy       string
	CanStorePassword bool // a master key is set
	CAFileSet        bool
}

func (s *Service) LDAP() LDAPView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := LDAPView{
		UpdatedAt: s.ldapAt, UpdatedBy: s.ldapBy, Enabled: slices.Contains(s.methods, auth.MethodLDAP),
		PasswordSource: s.passwordSourceLocked(), CanStorePassword: s.Secrets.Cipher() != nil, CAFileSet: s.CAFile != "",
	}
	if s.ldap != nil {
		ls := *s.ldap
		v.Settings = &ls
	}
	if !s.stored.IsZero() {
		v.PasswordUpdated, v.PasswordBy = s.stored.UpdatedAt, s.stored.UpdatedBy
	}
	return v
}

// Methods returns the enabled login methods, in order.
func (s *Service) Methods() []auth.Method {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.methods)
}

// DirectoryError is a refused save or a failed lookup: the LDAP server couldn't be used (unreachable, a refused
// service bind, a failed search). The API answers it 502 ldap_failed.
type DirectoryError struct {
	Err error
}

func (e *DirectoryError) Error() string { return e.Err.Error() }
func (e *DirectoryError) Unwrap() error { return e.Err }

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

const (
	maxField    = 1024 // bytes, for each LDAP setting
	maxPassword = 1024 // bytes
)

// LDAPInput is a save of the LDAP settings, with the bind password if the request gives one.
type LDAPInput struct {
	Settings     auth.LDAPSettings
	BindPassword *secrets.Value
}

func normalize(ls auth.LDAPSettings) (auth.LDAPSettings, error) {
	ls.URL = strings.TrimSpace(ls.URL)
	ls.BindDN = strings.TrimSpace(ls.BindDN)
	ls.BaseDN = strings.TrimSpace(ls.BaseDN)
	ls.UserFilter = strings.TrimSpace(ls.UserFilter)
	if ls.TLSMode == "" {
		ls.TLSMode = auth.LDAPTLSVerify
	}
	for field, v := range map[string]string{"url": ls.URL, "bind_dn": ls.BindDN, "base_dn": ls.BaseDN, "user_filter": ls.UserFilter} {
		if len(v) > maxField || strings.ContainsFunc(v, unicode.IsControl) {
			return ls, validation(field, "The %s is at most %d characters, with no control characters.", strings.ReplaceAll(field, "_", " "), maxField)
		}
	}
	if err := ls.Validate(); err != nil {
		field, _, _ := strings.Cut(err.Error(), " ")
		return ls, validation(field, "The %s.", strings.Replace(err.Error(), "_", " ", 1))
	}
	return ls, nil
}

// sameServer says whether two settings send the bind password to the same place, trusted the same way.
func sameServer(a, b *auth.LDAPSettings) bool {
	return a != nil && b != nil && strings.EqualFold(a.URL, b.URL) && a.TLSMode == b.TLSMode && a.AllowCNFallback == b.AllowCNFallback
}

// passwordPlan is what a save does with the bind password.
type passwordPlan struct {
	value  secrets.Value // the password to test with; zero if there is none
	has    bool
	store  bool   // seal and save value
	detail string // for the audit row: "stored", "confirmed" or ""
}

// planPassword applies the confirmation rule. The password is needed when the settings would send an existing
// password (stored or from the environment) to a server it wasn't entered for: the first save, a new URL, or a change
// to how the server's certificate is trusted. A password given replaces the stored one, or, when the environment
// variable is set, must match it, since the variable overrides a stored password.
func (s *Service) planPassword(before, after *auth.LDAPSettings, given *secrets.Value) (passwordPlan, error) {
	envPW, envSet := s.Secrets.LDAPBindPassword()
	s.mu.RLock()
	source := s.passwordSourceLocked()
	s.mu.RUnlock()
	newServer := !sameServer(before, after)

	if given == nil {
		if newServer && source != SourceNone {
			if envSet {
				return passwordPlan{}, validation("bind_password",
					"%s is set, so enter the password it holds to confirm it may be sent to this LDAP server.", secrets.VarLDAPBindPassword)
			}
			return passwordPlan{}, validation("bind_password",
				"Enter the bind password again: a saved password is only sent to the LDAP server it was entered for.")
		}
		pw, ok := s.bindPassword()
		return passwordPlan{value: pw, has: ok}, nil
	}
	if given.Len() > maxPassword {
		return passwordPlan{}, validation("bind_password", "The bind password is at most %d bytes.", maxPassword)
	}
	if envSet {
		if !given.Equal(envPW) {
			return passwordPlan{}, validation("bind_password",
				"That isn't the password in %s, which is used instead of a stored one. Enter that one, or change it there.", secrets.VarLDAPBindPassword)
		}
		return passwordPlan{value: envPW, has: true, detail: "confirmed"}, nil
	}
	if s.Secrets.Cipher() == nil {
		return passwordPlan{}, validation("bind_password",
			"The bind password can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Set %s instead.", secrets.VarLDAPBindPassword)
	}
	return passwordPlan{value: *given, has: true, store: true, detail: "stored"}, nil
}

// testBind runs a service bind with the given settings and password, as the check before a save.
func (s *Service) testBind(ctx context.Context, ls auth.LDAPSettings, pw secrets.Value, has bool) error {
	if !has || pw.IsZero() {
		return validation("bind_password", "LDAP login is on, so the LDAP settings need a bind password. Enter it.")
	}
	a, err := auth.NewLDAPAuthenticator(ls, func() (secrets.Value, bool) { return pw, true }, s.CAFile)
	if err != nil {
		return &DirectoryError{Err: err}
	}
	if err := a.CheckBind(ctx); err != nil {
		return &DirectoryError{Err: err}
	}
	return nil
}

// SaveLDAP saves the LDAP settings and, if given, the bind password. It needs settings.manage. While LDAP login is
// enabled, the new settings must pass a service bind first, so a typo can't lock LDAP users out. Audited as
// settings_update with the fields that changed, never the password.
func (s *Service) SaveLDAP(ctx context.Context, a rbac.Actor, in LDAPInput) error {
	after, err := normalize(in.Settings)
	if err != nil {
		return err
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	var before *auth.LDAPSettings
	if s.ldap != nil {
		b := *s.ldap
		before = &b
	}
	enabled := slices.Contains(s.methods, auth.MethodLDAP)
	s.mu.RUnlock()

	plan, err := s.planPassword(before, &after, in.BindPassword)
	if err != nil {
		return err
	}
	changed := changedFields(before, after)
	if len(changed) == 0 && !plan.store {
		return nil
	}
	if enabled {
		if err := s.testBind(ctx, after, plan.value, plan.has); err != nil {
			return err
		}
	}

	var stored StoredPassword
	now := s.now()
	err = s.do(ctx, a, func(t *txn) error {
		t.entry.Target = "settings:" + auth.LDAPSettingsKey
		t.entry.Detail["changed"] = changed
		if plan.detail != "" {
			t.entry.Detail["bind_password"] = plan.detail
		}
		value, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if err := t.q.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: auth.LDAPSettingsKey, Value: string(value), UpdatedAt: store.Millis(now), UpdatedBy: a.Username,
		}); err != nil {
			return err
		}
		if !plan.store {
			return nil
		}
		sealed, err := s.Secrets.Cipher().Seal(plan.value, passwordAAD)
		if err != nil {
			return err
		}
		stored = StoredPassword{Sealed: sealed, UpdatedAt: store.FromMillis(store.Millis(now)), UpdatedBy: a.Username}
		_, err = t.q.SetSettingSecret(ctx, db.SetSettingSecretParams{
			SecretCiphertext: sealed.Ciphertext, SecretNonce: sealed.Nonce,
			SecretKeyID:     sql.NullString{String: sealed.KeyID, Valid: true},
			SecretUpdatedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true},
			SecretUpdatedBy: sql.NullString{String: a.Username, Valid: true},
			Key:             auth.LDAPSettingsKey,
		})
		return err
	})
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ldap, s.ldapAt, s.ldapBy = &after, store.FromMillis(store.Millis(now)), a.Username
	if plan.store {
		s.stored = stored
	}
	if err := s.rebuildLocked(); err != nil {
		// Saved but not usable (an unreadable CA file, say): the previous chain stays in place until it is fixed.
		s.logger().Error("LDAP settings saved but the login chain couldn't be rebuilt", "err", err)
	}
	return nil
}

// changedFields lists the settings that differ, for the audit row. A first save lists them all.
func changedFields(before *auth.LDAPSettings, after auth.LDAPSettings) []string {
	var b auth.LDAPSettings
	if before != nil {
		b = *before
	}
	var out []string
	for _, f := range []struct {
		name string
		same bool
	}{
		{"url", b.URL == after.URL},
		{"bind_dn", b.BindDN == after.BindDN},
		{"base_dn", b.BaseDN == after.BaseDN},
		{"user_filter", b.UserFilter == after.UserFilter},
		{"tls_mode", b.TLSMode == after.TLSMode},
		{"allow_cn_fallback", b.AllowCNFallback == after.AllowCNFallback},
	} {
		if !f.same || before == nil {
			out = append(out, f.name)
		}
	}
	return out
}

// SaveMethods saves the enabled login methods, in order. It needs settings.manage. Local login must stay enabled:
// it is the way in when LDAP fails, which is why an enabled local admin must always exist. Turning LDAP on needs
// saved LDAP settings, a bind password, and a service bind that works. Audited as settings_update.
func (s *Service) SaveMethods(ctx context.Context, a rbac.Actor, methods []auth.Method) error {
	if err := auth.ValidateMethods(methods); err != nil {
		return validation("methods", "%s.", capitalise(err.Error()))
	}
	if !slices.Contains(methods, auth.MethodLocal) {
		return validation("methods", "Local login must stay on: it is the way in if LDAP can't be reached. It can come after LDAP.")
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	before := slices.Clone(s.methods)
	var ls *auth.LDAPSettings
	if s.ldap != nil {
		l := *s.ldap
		ls = &l
	}
	s.mu.RUnlock()
	if slices.Equal(before, methods) {
		return nil
	}
	if slices.Contains(methods, auth.MethodLDAP) && !slices.Contains(before, auth.MethodLDAP) {
		if ls == nil {
			return validation("methods", "Save the LDAP settings before turning LDAP login on.")
		}
		pw, ok := s.bindPassword()
		if err := s.testBind(ctx, *ls, pw, ok); err != nil {
			return err
		}
	}
	now := s.now()
	err := s.do(ctx, a, func(t *txn) error {
		t.entry.Target = "settings:" + auth.SettingsKey
		t.entry.Detail["changed"] = []string{"methods"}
		t.entry.Detail["methods"] = methods
		t.entry.Detail["previous_methods"] = before
		value, err := json.Marshal(auth.Settings{Methods: methods})
		if err != nil {
			return err
		}
		return t.q.UpsertSetting(ctx, db.UpsertSettingParams{
			Key: auth.SettingsKey, Value: string(value), UpdatedAt: store.Millis(now), UpdatedBy: a.Username,
		})
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.methods = slices.Clone(methods)
	return s.rebuildLocked()
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ErrNotConfigured means no LDAP settings have been saved, so there is no directory to ask.
var ErrNotConfigured = &rbac.Error{Code: rbac.CodeConflict, Message: "LDAP isn't set up yet: save the LDAP settings first."}

func (s *Service) ldapDirectory() (*auth.LDAPAuthenticator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.directory == nil {
		return nil, ErrNotConfigured
	}
	return s.directory, nil
}

// LookupUser asks the directory about a username with the service account, as the session recheck does: no password
// is needed. Whether or not LDAP login is enabled, the saved settings are used, so they can be tried before it is
// turned on. found is false if the directory has no single entry for the username.
func (s *Service) LookupUser(ctx context.Context, username string) (id *auth.Identity, found bool, err error) {
	dir, err := s.ldapDirectory()
	if err != nil {
		return nil, false, err
	}
	id, err = dir.Lookup(ctx, username)
	if errors.Is(err, auth.ErrNoSuchUser) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, &DirectoryError{Err: err}
	}
	return id, true, nil
}

// GroupCheck is what the directory says about a group DN.
type GroupCheck struct {
	Exists  bool
	Members int
}

// CheckGroup looks a group DN up with the service account. It is audited as ldap_mapping_check, since it asks the
// directory on an admin's behalf; the actor needs roles.manage, which the API checks.
func (s *Service) CheckGroup(ctx context.Context, a rbac.Actor, dn string) (GroupCheck, error) {
	dn = strings.TrimSpace(dn)
	if _, err := auth.NormalizeDN(dn); err != nil || dn == "" || len(dn) > maxField {
		return GroupCheck{}, validation("group_dn", "That isn't a valid LDAP distinguished name, such as cn=pihole-staff,ou=groups,dc=example,dc=com.")
	}
	dir, err := s.ldapDirectory()
	if err != nil {
		return GroupCheck{}, err
	}
	exists, members, err := dir.Group(ctx, dn)
	entry := audit.Entry{
		At: s.now(), UserID: a.UserID, Username: a.Username, Action: audit.ActionLDAPMappingCheck, IP: a.IP,
		Target: "ldap_group:" + dn, Detail: map[string]any{"exists": exists, "members": members},
	}
	if err != nil {
		entry.Err, entry.Detail = err, nil
		if rerr := s.Audit.Record(ctx, s.Store, entry); rerr != nil {
			return GroupCheck{}, rerr
		}
		return GroupCheck{}, &DirectoryError{Err: err}
	}
	if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
		return GroupCheck{}, err
	}
	return GroupCheck{Exists: exists, Members: members}, nil
}

// txn is one save in progress.
type txn struct {
	q     *db.Queries
	entry *audit.Entry
}

var errNoChange = errors.New("no change")

// do runs fn as one audited change that needs settings.manage, checked inside the transaction.
func (s *Service) do(ctx context.Context, a rbac.Actor, fn func(t *txn) error) error {
	now := s.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionSettingsUpdate, IP: a.IP, Detail: map[string]any{}}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := rbac.Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		if !set.CanGlobal(rbac.SettingsManage) {
			return rbac.Forbidden(rbac.SettingsManage)
		}
		if err := fn(&txn{q: q, entry: &entry}); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case errors.Is(err, errNoChange):
		return nil
	case rbac.IsCode(err, rbac.CodeForbidden):
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: entry.Target, Err: err, Detail: map[string]any{"attempted": audit.ActionSettingsUpdate}, IP: a.IP,
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
