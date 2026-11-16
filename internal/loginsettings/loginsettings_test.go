// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginsettings

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/auth/ldaptest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// fakeSecrets is the environment override and the master key.
type fakeSecrets struct {
	env    string // PIHOLE_RBAC_LDAP_BIND_PASSWORD, "" for unset
	cipher *secrets.Cipher
}

func (f *fakeSecrets) LDAPBindPassword() (secrets.Value, bool) {
	return secrets.NewValue([]byte(f.env)), f.env != ""
}
func (f *fakeSecrets) Cipher() *secrets.Cipher { return f.cipher }

type env struct {
	t      *testing.T
	ctx    context.Context
	st     *store.Store
	sec    *fakeSecrets
	audit  *bytes.Buffer
	svc    *Service
	dir    *ldaptest.Server
	f      ldaptest.Fixture
	admin  rbac.Actor // builtin admin
	viewer rbac.Actor // domains.view only
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c, err := secrets.NewCipher(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := ldaptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	e := &env{t: t, ctx: ctx, st: st, sec: &fakeSecrets{cipher: c}, audit: &bytes.Buffer{}, dir: dir, f: ldaptest.Example(dir)}
	e.svc = &Service{Store: st, Audit: audit.NewLogger(e.audit), Secrets: e.sec, Logger: quiet}
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		admin, err := q.GetBuiltinRole(ctx)
		if err != nil {
			return err
		}
		view, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "viewer", CreatedAt: 1})
		if err != nil {
			return err
		}
		if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: view, Permission: string(rbac.DomainsView)}); err != nil {
			return err
		}
		mk := func(name string, role int64) rbac.Actor {
			u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			return rbac.Actor{UserID: u.ID, Username: name, RoleIDs: []int64{role}, IP: "192.0.2.1"}
		}
		e.admin, e.viewer = mk("alice", admin.ID), mk("victor", view)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Load(ctx); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) settings() auth.LDAPSettings {
	return auth.LDAPSettings{URL: e.f.URL, BindDN: e.f.BindDN, BaseDN: e.f.BaseDN, UserFilter: e.f.UserFilter}
}

func pw(s string) *secrets.Value {
	v := secrets.NewValue([]byte(s))
	return &v
}

func wantField(t *testing.T, err error, field string) {
	t.Helper()
	e, ok := rbac.AsError(err)
	if !ok || e.Code != rbac.CodeValidation || e.Details["field"] != field {
		t.Fatalf("want validation_failed on %s, got %v", field, err)
	}
}

func (e *env) rows(action string) []db.AuditLog {
	e.t.Helper()
	var out []db.AuditLog
	for id := int64(1); ; id++ {
		r, err := e.st.Read().GetAudit(e.ctx, id)
		if err != nil {
			return out
		}
		if r.Action == action {
			out = append(out, r)
		}
	}
}

func (e *env) noPasswordAudited(passwords ...string) {
	e.t.Helper()
	var all strings.Builder
	all.WriteString(e.audit.String())
	for _, r := range e.rows(audit.ActionSettingsUpdate) {
		all.WriteString(r.Detail)
	}
	for _, p := range passwords {
		if strings.Contains(all.String(), p) {
			e.t.Errorf("password %q reached the audit log", p)
		}
	}
}

// TestPasswordOnlyGoesWhereConfirmed: a stored bind password is never sent to a server nobody entered it for.
func TestPasswordOnlyGoesWhereConfirmed(t *testing.T) {
	e := newEnv(t)
	evil, err := ldaptest.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer evil.Close()
	ldaptest.Example(evil)
	if err := e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLocal}); err != nil {
		t.Fatal(err) // no change, but no error either
	}

	// No password anywhere yet: the settings save freely, and nothing contacts the directory while LDAP login is off.
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings()}); err != nil {
		t.Fatal(err)
	}
	if e.dir.Binds() != 0 {
		t.Error("the directory was contacted while LDAP login is off")
	}
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw(e.f.BindPassword)}); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.LDAP(); v.PasswordSource != SourceStored || v.PasswordBy != "alice" {
		t.Errorf("after storing: %+v", v)
	}

	// The same server with another bind DN needs nothing more.
	same := e.settings()
	same.BindDN = "cn=other,dc=example,dc=local"
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: same}); err != nil {
		t.Fatal(err)
	}

	// Another server, or trusting the same one differently, needs the password again.
	moved := e.settings()
	moved.URL = evil.URL()
	wantField(t, e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: moved}), "bind_password")
	insecure := e.settings()
	insecure.TLSMode = auth.LDAPTLSInsecure
	wantField(t, e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: insecure}), "bind_password")
	if evil.Binds() != 0 {
		t.Fatal("the stored password was sent to a new server")
	}
	if got := e.svc.LDAP().Settings.URL; got != e.f.URL {
		t.Errorf("a refused save changed the URL to %s", got)
	}

	// With the password entered again, it goes.
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: moved, BindPassword: pw("for-the-other-server")}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.bindPassword(); got.Reveal() != "for-the-other-server" {
		t.Error("the new password wasn't stored")
	}
	e.noPasswordAudited(e.f.BindPassword, "for-the-other-server")
	rows := e.rows(audit.ActionSettingsUpdate)
	if len(rows) != 4 || !strings.Contains(rows[1].Detail, `"bind_password":"stored"`) {
		t.Errorf("settings_update rows: %+v", rows)
	}
}

func TestEnvironmentOverride(t *testing.T) {
	e := newEnv(t)
	e.sec.env = e.f.BindPassword

	// The variable is set, so the first save must confirm it may go to this server.
	wantField(t, e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings()}), "bind_password")
	wantField(t, e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw("wrong")}), "bind_password")
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw(e.f.BindPassword)}); err != nil {
		t.Fatal(err)
	}
	v := e.svc.LDAP()
	if v.PasswordSource != SourceEnvironment || !v.PasswordUpdated.IsZero() {
		t.Errorf("a confirmed variable isn't stored: %+v", v)
	}
	if rows := e.rows(audit.ActionSettingsUpdate); len(rows) != 1 || !strings.Contains(rows[0].Detail, `"bind_password":"confirmed"`) {
		t.Errorf("audit: %+v", rows)
	}
}

func TestNoMasterKey(t *testing.T) {
	e := newEnv(t)
	e.sec.cipher = nil
	if e.svc.LDAP().CanStorePassword {
		t.Error("CanStorePassword without a key")
	}
	err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw("x")})
	wantField(t, err, "bind_password")
	if !strings.Contains(err.Error(), "PIHOLE_RBAC_SECRET_KEY") {
		t.Errorf("message: %v", err)
	}
}

// TestLDAPLoginOnAndOff: turning LDAP on tests a service bind first; while it is on, new settings are tested before
// they are saved; the login chain and the recheck's directory follow every save.
func TestLDAPLoginOnAndOff(t *testing.T) {
	e := newEnv(t)
	login := func(user, password string) error {
		_, err := e.svc.Authenticator().Authenticate(e.ctx, user, password)
		return err
	}
	wantField(t, e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLDAP}), "methods") // local must stay
	wantField(t, e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLocal, auth.MethodLDAP}), "methods")

	// Settings saved with a wrong password: LDAP can't be turned on, and says why.
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw("wrong")}); err != nil {
		t.Fatal(err)
	}
	var de *DirectoryError
	if err := e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLocal, auth.MethodLDAP}); !errors.As(err, &de) {
		t.Fatalf("turning LDAP on with a wrong password: %v", err)
	}
	if slices.Contains(e.svc.Methods(), auth.MethodLDAP) || e.svc.Directory() != nil {
		t.Fatal("LDAP was turned on anyway")
	}

	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw(e.f.BindPassword)}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLDAP, auth.MethodLocal}); err != nil {
		t.Fatal(err)
	}
	if err := login("lucy", e.f.Password("lucy")); err != nil {
		t.Fatalf("LDAP login after turning it on: %v", err)
	}
	if e.svc.Directory() == nil {
		t.Error("no directory for the recheck")
	}

	// While it is on, a save that breaks the bind is refused and changes nothing.
	broken := e.settings()
	broken.BindDN = "cn=nobody,dc=example,dc=local"
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: broken}); !errors.As(err, &de) {
		t.Fatalf("saving settings that don't bind: %v", err)
	}
	if e.svc.LDAP().Settings.BindDN != e.f.BindDN {
		t.Error("a refused save changed the bind DN")
	}
	// A rotated password, entered here, applies to the next login without a restart.
	e.dir.SetPassword(e.f.BindDN, "rotated-password")
	if err := login("lucy", e.f.Password("lucy")); err == nil {
		t.Fatal("login worked with the old bind password")
	}
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw("rotated-password")}); err != nil {
		t.Fatal(err)
	}
	if err := login("lucy", e.f.Password("lucy")); err != nil {
		t.Fatalf("login after rotating: %v", err)
	}

	// Turning it off needs no test, and LDAP logins stop at once.
	if err := e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLocal}); err != nil {
		t.Fatal(err)
	}
	if err := login("lucy", e.f.Password("lucy")); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Errorf("LDAP login after turning it off: %v", err)
	}
	if e.svc.Directory() != nil {
		t.Error("the recheck still has a directory")
	}
	if rows := e.rows(audit.ActionSettingsUpdate); !strings.Contains(rows[len(rows)-1].Detail, `"previous_methods":["ldap","local"]`) {
		t.Errorf("last audit row: %+v", rows[len(rows)-1])
	}
	e.noPasswordAudited(e.f.BindPassword, "rotated-password", "wrong")
}

func TestNeedsSettingsManage(t *testing.T) {
	e := newEnv(t)
	err := e.svc.SaveLDAP(e.ctx, e.viewer, LDAPInput{Settings: e.settings()})
	if !rbac.IsCode(err, rbac.CodeForbidden) {
		t.Fatalf("viewer saving LDAP settings: %v", err)
	}
	if err := e.svc.SaveMethods(e.ctx, e.viewer, []auth.Method{auth.MethodLocal, auth.MethodLDAP}); err == nil {
		t.Fatal("viewer turned LDAP on")
	}
	if e.svc.LDAP().Settings != nil {
		t.Error("a refused save was kept")
	}
	if len(e.rows(audit.ActionPermissionDenied)) != 1 {
		t.Errorf("permission_denied rows: %d", len(e.rows(audit.ActionPermissionDenied)))
	}
}

func TestLookupAndCheckGroup(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.svc.LookupUser(e.ctx, "lucy"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("before any settings: %v", err)
	}
	// The tools use the saved settings even while LDAP login is off, so they can be tried first.
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw(e.f.BindPassword)}); err != nil {
		t.Fatal(err)
	}
	id, found, err := e.svc.LookupUser(e.ctx, "lucy")
	if err != nil || !found || id.DN != e.f.Users["lucy"] || len(id.Groups) != 2 {
		t.Errorf("lucy: %+v %v %v", id, found, err)
	}
	if _, found, err := e.svc.LookupUser(e.ctx, "nobody"); found || err != nil {
		t.Errorf("nobody: %v %v", found, err)
	}

	for _, tt := range []struct {
		dn      string
		exists  bool
		members int
	}{{e.f.StaffGroup, true, 2}, {e.f.EmptyGroup, true, 0}, {"cn=missing,ou=groups,dc=example,dc=local", false, 0}} {
		got, err := e.svc.CheckGroup(e.ctx, e.admin, tt.dn)
		if err != nil || got.Exists != tt.exists || got.Members != tt.members {
			t.Errorf("%s: %+v %v", tt.dn, got, err)
		}
	}
	_, err = e.svc.CheckGroup(e.ctx, e.admin, "not a dn")
	wantField(t, err, "group_dn")
	if n := len(e.rows(audit.ActionLDAPMappingCheck)); n != 3 {
		t.Errorf("ldap_mapping_check rows: %d", n)
	}

	e.dir.Close()
	var de *DirectoryError
	if _, err := e.svc.CheckGroup(e.ctx, e.admin, e.f.StaffGroup); !errors.As(err, &de) {
		t.Errorf("directory down: %v", err)
	}
	if _, _, err := e.svc.LookupUser(e.ctx, "lucy"); !errors.As(err, &de) {
		t.Errorf("lookup with the directory down: %v", err)
	}
}

// TestLoad: what startup accepts, and that a stored password survives a restart.
func TestLoad(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.SaveLDAP(e.ctx, e.admin, LDAPInput{Settings: e.settings(), BindPassword: pw(e.f.BindPassword)}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SaveMethods(e.ctx, e.admin, []auth.Method{auth.MethodLocal, auth.MethodLDAP}); err != nil {
		t.Fatal(err)
	}
	again := &Service{Store: e.st, Audit: audit.NewLogger(io.Discard), Secrets: e.sec, Logger: e.svc.Logger}
	if err := again.Load(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := again.Authenticator().Authenticate(e.ctx, "mark", e.f.Password("mark")); err != nil {
		t.Errorf("LDAP login after a restart: %v", err)
	}
	// Under another master key the stored password can't be read, and says so rather than sending garbage.
	other, _ := secrets.NewCipher(bytes.Repeat([]byte{8}, secrets.KeySize))
	again.Secrets = &fakeSecrets{cipher: other}
	if _, ok := again.bindPassword(); ok {
		t.Error("decrypted under the wrong key")
	}

	ldapJSON := `{"url":"ldaps://dc01.example.local","bind_dn":"cn=svc,dc=example,dc=local","base_dn":"dc=example,dc=local","user_filter":"(uid=%s)"}`
	for _, tt := range []struct {
		name     string
		settings map[string]string
		wantErr  string
	}{
		{name: "defaults: local only"},
		{name: "local and ldap", settings: map[string]string{"auth": `{"methods":["local","ldap"]}`, "ldap": ldapJSON}},
		{name: "ldap enabled, not configured", settings: map[string]string{"auth": `{"methods":["ldap"]}`}, wantErr: "no LDAP settings"},
		{name: "ldap settings invalid", settings: map[string]string{
			"auth": `{"methods":["ldap"]}`,
			"ldap": `{"url":"http://dc01","bind_dn":"cn=svc,dc=x","base_dn":"dc=x","user_filter":"(uid=%s)"}`,
		}, wantErr: "url"},
		{name: "login settings invalid", settings: map[string]string{"auth": `{"methods":[]}`}, wantErr: "at least one"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st, err := store.Open(e.ctx, store.Options{DataDir: t.TempDir(), Logger: e.svc.Logger})
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			for k, v := range tt.settings {
				if err := st.WithTx(e.ctx, func(q *db.Queries) error {
					return q.UpsertSetting(e.ctx, db.UpsertSettingParams{Key: k, Value: v, UpdatedAt: time.Now().UnixMilli()})
				}); err != nil {
					t.Fatal(err)
				}
			}
			svc := &Service{Store: st, Audit: audit.NewLogger(io.Discard), Secrets: &fakeSecrets{}, Logger: e.svc.Logger}
			err = svc.Load(e.ctx)
			if tt.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// TestScheduleGroupWindowMax: the group window maximum defaults to a day, is refused outside 5 minutes to 365 days,
// is audited when it changes, is kept by a save that leaves it out, and survives a restart.
func TestScheduleGroupWindowMax(t *testing.T) {
	e := newEnv(t)
	if got := e.svc.ScheduleLimits().MaxGroupWindow; got != 24*time.Hour {
		t.Errorf("default %s", got)
	}
	if g := e.svc.General(); g.ScheduleGroupWindowMaxMinutes == nil || *g.ScheduleGroupWindowMaxMinutes != 1440 {
		t.Errorf("General shows %v", g.ScheduleGroupWindowMaxMinutes)
	}
	save := func(m *int) error {
		return e.svc.SaveGeneral(e.ctx, e.admin, General{SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60,
			AuditRetentionDays: DefaultRetentionDays, ScheduleGroupWindowMaxMinutes: m})
	}
	ptr := func(n int) *int { return &n }
	for _, m := range []int{0, 4, 365*24*60 + 1} {
		wantField(t, save(ptr(m)), "schedule_group_window_max_minutes")
	}
	if err := save(ptr(90)); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.ScheduleLimits().MaxGroupWindow; got != 90*time.Minute {
		t.Errorf("after saving 90: %s", got)
	}
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1)
	if err != nil || len(rows) != 1 || rows[0].Action != audit.ActionSettingsUpdate ||
		!strings.Contains(rows[0].Detail, `"changed":["schedule_group_window_max_minutes"]`) ||
		!strings.Contains(rows[0].Detail, `"schedule_group_window_max_minutes":90`) {
		t.Errorf("audit: %+v, %v", rows, err)
	}
	if err := save(nil); err != nil {
		t.Fatal(err)
	}
	if got := e.svc.ScheduleLimits().MaxGroupWindow; got != 90*time.Minute {
		t.Errorf("a save without it changed it: %s", got)
	}
	again := &Service{Store: e.st, Audit: audit.NewLogger(io.Discard), Secrets: e.sec, Logger: e.svc.Logger}
	if err := again.Load(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got := again.ScheduleLimits().MaxGroupWindow; got != 90*time.Minute {
		t.Errorf("after a restart: %s", got)
	}
}

// TestClientTempSettings: the temporary client change maximum defaults to 7 days and the reason to required; the
// maximum is refused outside 5 minutes to 365 days; both are audited when they change, kept by a save that leaves
// them out, and survive a restart.
func TestClientTempSettings(t *testing.T) {
	e := newEnv(t)
	if l := e.svc.ClientOverrideLimits(); l.Max != 7*24*time.Hour || !l.ReasonRequired {
		t.Errorf("defaults %+v", l)
	}
	g := e.svc.General()
	if g.ClientTempMaxMinutes == nil || *g.ClientTempMaxMinutes != 7*24*60 || g.ClientTempReasonRequired == nil || !*g.ClientTempReasonRequired {
		t.Errorf("General shows %v, %v", g.ClientTempMaxMinutes, g.ClientTempReasonRequired)
	}
	save := func(m *int, reason *bool) error {
		return e.svc.SaveGeneral(e.ctx, e.admin, General{SessionLifetimeMinutes: 480, IdleTimeoutMinutes: 60,
			AuditRetentionDays: DefaultRetentionDays, ClientTempMaxMinutes: m, ClientTempReasonRequired: reason})
	}
	ptr := func(n int) *int { return &n }
	no := false
	for _, m := range []int{0, 4, 365*24*60 + 1} {
		wantField(t, save(ptr(m), nil), "client_temp_max_minutes")
	}
	if err := save(ptr(120), &no); err != nil {
		t.Fatal(err)
	}
	if l := e.svc.ClientOverrideLimits(); l.Max != 2*time.Hour || l.ReasonRequired {
		t.Errorf("after saving 120 and no reason: %+v", l)
	}
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1)
	if err != nil || len(rows) != 1 || rows[0].Action != audit.ActionSettingsUpdate ||
		!strings.Contains(rows[0].Detail, `"client_temp_max_minutes"`) || !strings.Contains(rows[0].Detail, `"client_temp_reason_required"`) ||
		!strings.Contains(rows[0].Detail, `"client_temp_max_minutes":120`) || !strings.Contains(rows[0].Detail, `"client_temp_reason_required":false`) {
		t.Errorf("audit: %+v, %v", rows, err)
	}
	if err := save(nil, nil); err != nil {
		t.Fatal(err)
	}
	if l := e.svc.ClientOverrideLimits(); l.Max != 2*time.Hour || l.ReasonRequired {
		t.Errorf("a save without them changed them: %+v", l)
	}
	again := &Service{Store: e.st, Audit: audit.NewLogger(io.Discard), Secrets: e.sec, Logger: e.svc.Logger}
	if err := again.Load(e.ctx); err != nil {
		t.Fatal(err)
	}
	if l := again.ClientOverrideLimits(); l.Max != 2*time.Hour || l.ReasonRequired {
		t.Errorf("after a restart: %+v", l)
	}
	yes := true
	if err := save(nil, &yes); err != nil {
		t.Fatal(err)
	}
	if l := e.svc.ClientOverrideLimits(); !l.ReasonRequired || l.Max != 2*time.Hour {
		t.Errorf("after turning the reason back on: %+v", l)
	}
}
