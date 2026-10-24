// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type svcEnv struct {
	t      *testing.T
	ctx    context.Context
	st     *store.Store
	svc    *Service
	pool   *Pool
	pw     *fakePasswords
	admin  rbac.Actor // holds instances.manage through the builtin admin role
	viewer rbac.Actor // holds only domains.view
}

func newSvcEnv(t *testing.T) *svcEnv {
	t.Helper()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, store.Options{DataDir: t.TempDir(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	pw := &fakePasswords{m: map[string]string{"PIHOLE1": password, "PIHOLE2": password}}
	pool := New(Options{Passwords: pw, Timeout: 2 * time.Second, Logger: logger})
	t.Cleanup(func() { pool.Close(context.Background()) })
	e := &svcEnv{
		t: t, ctx: ctx, st: st, pool: pool, pw: pw,
		svc: &Service{Store: st, Audit: audit.NewLogger(io.Discard), Pool: pool, Now: func() time.Time { return t0 }},
	}
	e.tx(func(q *db.Queries) error {
		adminRole, err := q.GetBuiltinRole(ctx)
		if err != nil {
			return err
		}
		viewRole, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "viewer", CreatedAt: 1})
		if err != nil {
			return err
		}
		if err := q.AddRoleGrantAll(ctx, db.AddRoleGrantAllParams{RoleID: viewRole, Permission: string(rbac.DomainsView)}); err != nil {
			return err
		}
		mk := func(name string, role int64) rbac.Actor {
			u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1})
			if err != nil {
				t.Fatal(err)
			}
			return rbac.Actor{UserID: u.ID, Username: name, RoleIDs: []int64{role}, IP: "192.0.2.1"}
		}
		e.admin, e.viewer = mk("alice", adminRole.ID), mk("victor", viewRole)
		return nil
	})
	return e
}

func (e *svcEnv) tx(fn func(q *db.Queries) error) {
	e.t.Helper()
	if err := e.st.WithTx(e.ctx, fn); err != nil {
		e.t.Fatal(err)
	}
}

func (e *svcEnv) create(name, env, url string) Instance {
	e.t.Helper()
	inst, err := e.svc.Create(e.ctx, e.admin, Input{Name: name, BaseURL: url, EnvName: env, Password: e.envConfirmation(env)})
	if err != nil {
		e.t.Fatalf("Create %s: %v", name, err)
	}
	return inst
}

// envConfirmation is the password of env's variable, which a create or edit must give to start using it, or nil when
// the variable isn't set.
func (e *svcEnv) envConfirmation(env string) *secrets.Value {
	if v, ok := e.pw.InstancePassword(env); ok {
		return &v
	}
	return nil
}

// lastAudit returns the newest audit row.
func (e *svcEnv) lastAudit() db.AuditLog {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1)
	if err != nil || len(rows) == 0 {
		e.t.Fatalf("no audit rows: %v", err)
	}
	return rows[0]
}

func (e *svcEnv) auditCount() int {
	e.t.Helper()
	rows, err := e.st.Read().ListRecentAudit(e.ctx, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(rows)
}

func detail(t *testing.T, row db.AuditLog) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(row.Detail), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func wantCode(t *testing.T, err error, code rbac.Code, field string) {
	t.Helper()
	e, ok := rbac.AsError(err)
	if !ok || e.Code != code {
		t.Fatalf("err = %v, want code %s", err, code)
	}
	if field != "" && e.Details["field"] != field {
		t.Fatalf("field = %v, want %s (%s)", e.Details["field"], field, e.Message)
	}
}

func TestCreate(t *testing.T) {
	e := newSvcEnv(t)
	inst := e.create("pihole1", "PIHOLE1", " https://pi1.lan/ ")
	if inst.Enabled || inst.BaseURL != "https://pi1.lan" || inst.TLSMode != piholeapi.TLSVerify || inst.ID == 0 {
		t.Fatalf("created %+v", inst)
	}
	got, err := e.svc.Get(e.ctx, inst.ID)
	if err != nil || !got.equal(inst) {
		t.Fatalf("Get = %+v, %v; want %+v", got, err, inst)
	}
	row := e.lastAudit()
	if row.Action != audit.ActionInstanceCreate || row.Target != "instance:pihole1" || row.Result != audit.ResultSuccess ||
		row.InstanceID.Int64 != inst.ID || row.InstanceName != "pihole1" {
		t.Errorf("audit row %+v", row)
	}
	if _, ok := e.pool.Health(inst.ID); ok {
		t.Error("a disabled instance is in the pool")
	}

	t.Run("conflicts", func(t *testing.T) {
		_, err := e.svc.Create(e.ctx, e.admin, Input{Name: "PiHole1", BaseURL: "http://x", EnvName: "OTHER"})
		wantCode(t, err, rbac.CodeConflict, "name")
		_, err = e.svc.Create(e.ctx, e.admin, Input{Name: "other", BaseURL: "http://x", EnvName: "PIHOLE1", Password: e.envConfirmation("PIHOLE1")})
		wantCode(t, err, rbac.CodeConflict, "env_name")
	})
}

func TestInputValidation(t *testing.T) {
	e := newSvcEnv(t)
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(notPEM, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	ph := piholetest.NewTLS(t, password)
	goodCA := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(goodCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ph.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	ok := Input{Name: "pi", BaseURL: "https://pi.lan", EnvName: "PI"}
	tests := []struct {
		name  string
		edit  func(*Input)
		field string // "" means valid
	}{
		{"valid", func(*Input) {}, ""},
		{"valid with ca file", func(in *Input) { in.CAFile = goodCA }, ""},
		{"empty name", func(in *Input) { in.Name = "  " }, "name"},
		{"long name", func(in *Input) { in.Name = strings.Repeat("x", 65) }, "name"},
		{"control character", func(in *Input) { in.Name = "pi\nhole" }, "name"},
		{"bad url", func(in *Input) { in.BaseURL = "pi.lan" }, "base_url"},
		{"url with admin", func(in *Input) { in.BaseURL = "https://pi.lan/admin" }, "base_url"},
		{"lowercase env", func(in *Input) { in.EnvName = "pi" }, "env_name"},
		{"env with dash", func(in *Input) { in.EnvName = "PI-1" }, "env_name"},
		{"bad tls mode", func(in *Input) { in.TLSMode = "maybe" }, "tls_mode"},
		{"ca with insecure", func(in *Input) { in.CAFile, in.TLSMode = goodCA, piholeapi.TLSInsecure }, "ca_file"},
		{"ca with http", func(in *Input) { in.CAFile, in.BaseURL = goodCA, "http://pi.lan" }, "ca_file"},
		{"relative ca", func(in *Input) { in.CAFile = "ca.pem" }, "ca_file"},
		{"missing ca", func(in *Input) { in.CAFile = filepath.Join(dir, "missing.pem") }, "ca_file"},
		{"ca without pem", func(in *Input) { in.CAFile = notPEM }, "ca_file"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := ok
			in.Name, in.EnvName = in.Name+string(rune('a'+i)), in.EnvName+string(rune('A'+i))
			tt.edit(&in)
			_, err := e.svc.Create(e.ctx, e.admin, in)
			if tt.field == "" {
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				return
			}
			wantCode(t, err, rbac.CodeValidation, tt.field)
		})
	}
}

// Every change needs instances.manage; a refusal is audited and never reaches a Pi-hole.
func TestForbidden(t *testing.T) {
	e := newSvcEnv(t)
	ph := piholetest.New(t, password)
	inst := e.create("pihole1", "PIHOLE1", ph.URL)

	calls := map[string]func() error{
		"create": func() error {
			_, err := e.svc.Create(e.ctx, e.viewer, Input{Name: "x", BaseURL: "http://x", EnvName: "X"})
			return err
		},
		"update": func() error {
			_, err := e.svc.Update(e.ctx, e.viewer, inst.ID, Input{Name: "x", BaseURL: ph.URL, EnvName: "PIHOLE1"})
			return err
		},
		"enable": func() error {
			_, err := e.svc.SetEnabled(e.ctx, e.viewer, inst.ID, true)
			return err
		},
		"delete": func() error { return e.svc.Delete(e.ctx, e.viewer, inst.ID) },
		"test":   func() error { return e.svc.Test(e.ctx, e.viewer, inst.ID) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			wantCode(t, call(), rbac.CodeForbidden, "")
			row := e.lastAudit()
			if row.Action != audit.ActionPermissionDenied || row.Username != "victor" {
				t.Errorf("audit row %+v", row)
			}
		})
	}
	if ph.Logins() != 0 {
		t.Errorf("a refused request reached Pi-hole (%d logins)", ph.Logins())
	}
	if got, _ := e.svc.Get(e.ctx, inst.ID); !got.equal(inst) {
		t.Errorf("instance changed: %+v", got)
	}
}

func TestEnable(t *testing.T) {
	e := newSvcEnv(t)
	ph := piholetest.New(t, password)
	wrong := piholetest.New(t, "something else")
	e.pw.set("NOPASS", "")

	t.Run("refused when the test fails", func(t *testing.T) {
		for _, tt := range []struct {
			env, url string
			wantIs   error
		}{
			{"NOPASS", ph.URL, ErrNoPassword},
			{"PIHOLE2", wrong.URL, piholeapi.ErrAuthRejected},
		} {
			inst := e.create("i-"+tt.env, tt.env, tt.url)
			_, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true)
			var te *TestError
			if !errors.As(err, &te) || !errors.Is(err, tt.wantIs) {
				t.Fatalf("%s: err = %v, want a TestError wrapping %v", tt.env, err, tt.wantIs)
			}
			if got, _ := e.svc.Get(e.ctx, inst.ID); got.Enabled {
				t.Errorf("%s: enabled after a failed test", tt.env)
			}
			row := e.lastAudit()
			if row.Action != audit.ActionInstanceEnable || row.Result != audit.ResultFailure ||
				detail(t, row)["error"] != "connection test failed: "+Kind(tt.wantIs) {
				t.Errorf("%s: audit row %+v", tt.env, row)
			}
		}
	})

	t.Run("enabled when the test passes", func(t *testing.T) {
		inst := e.create("pihole1", "PIHOLE1", ph.URL)
		got, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true)
		if err != nil || !got.Enabled {
			t.Fatalf("SetEnabled = %+v, %v", got, err)
		}
		if ph.Sessions() != 0 {
			t.Error("the connection test left a session open")
		}
		if row := e.lastAudit(); row.Action != audit.ActionInstanceEnable || row.Result != audit.ResultSuccess {
			t.Errorf("audit row %+v", row)
		}
		if err := e.pool.Do(e.ctx, inst.ID, status); err != nil {
			t.Fatalf("pool: %v", err)
		}

		before := e.auditCount()
		if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
			t.Fatal(err)
		}
		if e.auditCount() != before {
			t.Error("enabling an enabled instance was audited")
		}
	})
}

func TestDisable(t *testing.T) {
	e := newSvcEnv(t)
	ph := piholetest.New(t, password)
	inst := e.create("pihole1", "PIHOLE1", ph.URL)
	if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.Do(e.ctx, inst.ID, status); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, false)
	if err != nil || got.Enabled {
		t.Fatalf("SetEnabled(false) = %+v, %v", got, err)
	}
	e.pool.retiring.Wait()
	if _, ok := e.pool.Health(inst.ID); ok || ph.Sessions() != 0 {
		t.Errorf("still in the pool (%v) or logged in (%d sessions)", ok, ph.Sessions())
	}
	if row := e.lastAudit(); row.Action != audit.ActionInstanceDisable {
		t.Errorf("audit row %+v", row)
	}
}

func TestUpdate(t *testing.T) {
	e := newSvcEnv(t)
	a := piholetest.New(t, password)
	b := piholetest.New(t, password)
	down, hits := countingDown(t)

	inst := e.create("pihole1", "PIHOLE1", a.URL)
	in := Input{Name: "pihole1", BaseURL: a.URL, EnvName: "PIHOLE1"}

	t.Run("no change is not audited", func(t *testing.T) {
		before := e.auditCount()
		if _, err := e.svc.Update(e.ctx, e.admin, inst.ID, in); err != nil {
			t.Fatal(err)
		}
		if e.auditCount() != before {
			t.Error("an unchanged update was audited")
		}
	})

	t.Run("disabled instances are saved without a test", func(t *testing.T) {
		bad := in
		bad.BaseURL = down.URL
		bad.Password = e.envConfirmation("PIHOLE1") // a new address needs the password again
		if _, err := e.svc.Update(e.ctx, e.admin, inst.ID, bad); err != nil {
			t.Fatal(err)
		}
		if hits.Load() != 0 {
			t.Error("a disabled instance was tested")
		}
		back := in
		back.Password = e.envConfirmation("PIHOLE1")
		if _, err := e.svc.Update(e.ctx, e.admin, inst.ID, back); err != nil {
			t.Fatal(err)
		}
	})

	if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := e.pool.Do(e.ctx, inst.ID, status); err != nil {
		t.Fatal(err)
	}
	logins := a.Logins()

	t.Run("a rename keeps the connection", func(t *testing.T) {
		renamed := in
		renamed.Name = "kitchen"
		got, err := e.svc.Update(e.ctx, e.admin, inst.ID, renamed)
		if err != nil || got.Name != "kitchen" {
			t.Fatalf("Update = %+v, %v", got, err)
		}
		if err := e.pool.Do(e.ctx, inst.ID, status); err != nil || a.Logins() != logins {
			t.Errorf("pool: err %v, logins %d (want %d: no test, session kept)", err, a.Logins(), logins)
		}
		row := e.lastAudit()
		if d := detail(t, row); row.Target != "instance:kitchen" || d["renamed_from"] != "pihole1" || d["changed"] != nil {
			t.Errorf("audit row %+v, detail %v", row, d)
		}
		in = renamed
	})

	t.Run("a connection change that fails its test is refused", func(t *testing.T) {
		bad := in
		bad.BaseURL = down.URL
		bad.Password = e.envConfirmation("PIHOLE1")
		_, err := e.svc.Update(e.ctx, e.admin, inst.ID, bad)
		var te *TestError
		if !errors.As(err, &te) {
			t.Fatalf("err = %v, want a TestError", err)
		}
		if got, _ := e.svc.Get(e.ctx, inst.ID); got.BaseURL != a.URL {
			t.Errorf("base URL saved anyway: %s", got.BaseURL)
		}
		if row := e.lastAudit(); row.Action != audit.ActionInstanceUpdate || row.Result != audit.ResultFailure {
			t.Errorf("audit row %+v", row)
		}
	})

	t.Run("a connection change that passes is applied to the pool", func(t *testing.T) {
		moved := in
		moved.BaseURL = b.URL
		moved.Password = e.envConfirmation("PIHOLE1")
		got, err := e.svc.Update(e.ctx, e.admin, inst.ID, moved)
		if err != nil || got.BaseURL != b.URL {
			t.Fatalf("Update = %+v, %v", got, err)
		}
		e.pool.retiring.Wait()
		if a.Sessions() != 0 {
			t.Error("the old client is still logged in")
		}
		bLogins := b.Logins()
		if err := e.pool.Do(e.ctx, inst.ID, status); err != nil || b.Logins() != bLogins+1 {
			t.Errorf("pool isn't using the new URL: err %v, logins %d", err, b.Logins())
		}
		if d := detail(t, e.lastAudit()); len(d["changed"].([]any)) != 1 || d["changed"].([]any)[0] != "base_url" {
			t.Errorf("detail %v", d)
		}
	})

	t.Run("unknown instance", func(t *testing.T) {
		_, err := e.svc.Update(e.ctx, e.admin, 999, in)
		wantCode(t, err, rbac.CodeNotFound, "")
	})
}

func TestDelete(t *testing.T) {
	e := newSvcEnv(t)
	ph := piholetest.New(t, password)
	used := e.create("used", "PIHOLE1", ph.URL)
	free := e.create("free", "PIHOLE2", ph.URL)
	if _, err := e.svc.SetEnabled(e.ctx, e.admin, free.ID, true); err != nil {
		t.Fatal(err)
	}

	e.tx(func(q *db.Queries) error {
		role, err := q.CreateRole(e.ctx, db.CreateRoleParams{Name: "lab staff", CreatedAt: 1})
		if err != nil {
			return err
		}
		if err := q.InsertGrant(e.ctx, db.InsertGrantParams{
			RoleID: role, Permission: string(rbac.DomainsView), ScopeType: "instance",
			InstanceID: sql.NullInt64{Int64: used.ID, Valid: true},
		}); err != nil {
			return err
		}
		g, err := q.CreateInstanceGroup(e.ctx, db.CreateInstanceGroupParams{Name: "site a", Mode: "independent", CreatedAt: 1})
		if err != nil {
			return err
		}
		return q.AddInstanceGroupMember(e.ctx, db.AddInstanceGroupMemberParams{GroupID: g, InstanceID: used.ID})
	})

	err := e.svc.Delete(e.ctx, e.admin, used.ID)
	wantCode(t, err, rbac.CodeConflict, "")
	if msg := err.Error(); !strings.Contains(msg, `role "lab staff"`) || !strings.Contains(msg, `group "site a"`) {
		t.Errorf("message %q doesn't list the uses", msg)
	}
	if _, err := e.svc.Get(e.ctx, used.ID); err != nil {
		t.Errorf("refused delete removed the instance: %v", err)
	}

	if err := e.svc.Delete(e.ctx, e.admin, free.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Get(e.ctx, free.ID)
	wantCode(t, err, rbac.CodeNotFound, "")
	if _, ok := e.pool.Health(free.ID); ok {
		t.Error("deleted instance is still in the pool")
	}
	row := e.lastAudit()
	if row.Action != audit.ActionInstanceDelete || row.InstanceName != "free" || row.InstanceID.Valid ||
		detail(t, row)["instance_id"] != float64(free.ID) {
		t.Errorf("audit row %+v", row)
	}

	wantCode(t, e.svc.Delete(e.ctx, e.admin, free.ID), rbac.CodeNotFound, "")
}

func TestLoadPool(t *testing.T) {
	e := newSvcEnv(t)
	ph := piholetest.New(t, password)
	on := e.create("on", "PIHOLE1", ph.URL)
	off := e.create("off", "PIHOLE2", ph.URL)
	e.tx(func(q *db.Queries) error {
		return q.SetInstanceEnabled(e.ctx, db.SetInstanceEnabledParams{Enabled: true, ID: on.ID})
	})

	fresh := New(Options{Passwords: e.pw, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(func() { fresh.Close(context.Background()) })
	svc := &Service{Store: e.st, Audit: e.svc.Audit, Pool: fresh}
	if err := svc.LoadPool(e.ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.Health(on.ID); !ok {
		t.Error("enabled instance not loaded")
	}
	if _, ok := fresh.Health(off.ID); ok {
		t.Error("disabled instance loaded")
	}
}
