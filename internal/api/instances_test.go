// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const piholePassword = "pihole app password"

// withInstances gives the server an instance service whose secrets come from env (variable name to value).
func withInstances(t *testing.T, env map[string]string) func(*Options) {
	return func(o *Options) {
		sec, err := secrets.Load(secrets.Options{
			DataDir: t.TempDir(),
			Getenv:  func(k string) string { return env[k] },
			Environ: func() []string {
				var out []string
				for k, v := range env {
					out = append(out, k+"="+v)
				}
				return out
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		pool := instances.New(instances.Options{Passwords: sec, Timeout: 2 * time.Second, Logger: o.Logger})
		t.Cleanup(func() { pool.Close(context.Background()) })
		o.Secrets = sec
		o.Instances = &instances.Service{Store: o.Store, Audit: o.Audit, Pool: pool}
	}
}

func instancePath(id int64, suffix string) string {
	return "/api/v1/instances/" + strconv.FormatInt(id, 10) + suffix
}

func mustStatus(t *testing.T, res response, want int) {
	t.Helper()
	if res.Code != want {
		t.Fatalf("status %d, want %d: %s", res.Code, want, res.Body)
	}
}

func errorDetails(t *testing.T, res response) map[string]any {
	t.Helper()
	d := decode[gen.Error](t, res).Error.Details
	if d == nil {
		t.Fatalf("no details in %s", res.Body)
	}
	return *d
}

func TestInstanceLifecycle(t *testing.T) {
	ph := piholetest.New(t, piholePassword)
	e := newTestEnv(t, withInstances(t, map[string]string{secrets.InstanceVar("PIHOLE1"): piholePassword}))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "pihole1", BaseUrl: ph.URL + "/", EnvName: ptr("PIHOLE1"), Password: ptr(piholePassword)})
	mustStatus(t, res, http.StatusCreated)
	inst := decode[gen.Instance](t, res)
	if inst.Enabled || inst.BaseUrl != ph.URL || inst.TlsMode != gen.InstanceTlsModeVerify || inst.Health != nil ||
		inst.PasswordVariable == nil || *inst.PasswordVariable != "PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD" || !inst.PasswordSet {
		t.Fatalf("created %+v", inst)
	}

	if list := decode[gen.InstanceList](t, c.do(http.MethodGet, "/api/v1/instances", nil)); len(list.Instances) != 1 || !reflect.DeepEqual(list.Instances[0], inst) || list.CanStorePasswords {
		t.Errorf("list %+v", list)
	}
	if got := decode[gen.Instance](t, c.do(http.MethodGet, instancePath(inst.Id, ""), nil)); !reflect.DeepEqual(got, inst) {
		t.Errorf("get %+v", got)
	}
	if tl := decode[gen.TargetList](t, c.do(http.MethodGet, "/api/v1/targets", nil)); len(tl.Targets) != 0 {
		t.Errorf("a disabled instance is a target: %+v", tl)
	}

	res = c.do(http.MethodPost, instancePath(inst.Id, "/test"), nil)
	mustStatus(t, res, http.StatusOK)
	if tr := decode[gen.InstanceTestResult](t, res); !tr.Ok || tr.Error != nil {
		t.Errorf("test %+v", tr)
	}

	res = c.do(http.MethodPost, instancePath(inst.Id, "/enable"), nil)
	mustStatus(t, res, http.StatusOK)
	if got := decode[gen.Instance](t, res); !got.Enabled || got.Health == nil || got.Health.State != gen.InstanceHealthState(instances.StateUnknown) {
		t.Errorf("enabled %+v", got)
	}

	// After a call through the pool, the health shows it.
	if err := e.srv.Instances.Pool.Do(context.Background(), inst.Id, func(ctx context.Context, cl *piholeapi.Client) error {
		_, err := cl.GetStatus(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tl := decode[gen.TargetList](t, c.do(http.MethodGet, "/api/v1/targets", nil))
	want := "i-" + strconv.FormatInt(inst.Id, 10)
	if len(tl.Targets) != 1 || tl.Targets[0].Id != want || tl.Targets[0].Kind != gen.TargetKindInstance ||
		tl.Targets[0].Name != "pihole1" || tl.Targets[0].Health == nil || tl.Targets[0].Health.State != gen.TargetHealthState(instances.StateUp) ||
		tl.Targets[0].Health.LastSuccess == nil {
		t.Fatalf("targets %s", mustJSON(t, tl))
	}

	res = c.do(http.MethodPut, instancePath(inst.Id, ""), gen.InstanceInput{Name: "kitchen", BaseUrl: ph.URL, EnvName: ptr("PIHOLE1")})
	mustStatus(t, res, http.StatusOK)
	if got := decode[gen.Instance](t, res); got.Name != "kitchen" || !got.Enabled {
		t.Errorf("updated %+v", got)
	}

	res = c.do(http.MethodPost, instancePath(inst.Id, "/disable"), nil)
	mustStatus(t, res, http.StatusOK)
	if got := decode[gen.Instance](t, res); got.Enabled || got.Health != nil {
		t.Errorf("disabled %+v", got)
	}

	mustStatus(t, c.do(http.MethodDelete, instancePath(inst.Id, ""), nil), http.StatusNoContent)
	mustStatus(t, c.do(http.MethodGet, instancePath(inst.Id, ""), nil), http.StatusNotFound)

	var actions []string
	for _, a := range e.auditActions() {
		if a != audit.ActionLogin {
			actions = append(actions, a)
		}
	}
	wantActions := []string{audit.ActionInstanceCreate, audit.ActionInstanceEnable, audit.ActionInstanceUpdate,
		audit.ActionInstanceDisable, audit.ActionInstanceDelete}
	if !slices.Equal(actions, wantActions) {
		t.Errorf("audit actions %v, want %v", actions, wantActions)
	}
}

func TestInstanceErrors(t *testing.T) {
	good := piholetest.New(t, piholePassword)
	wrong := piholetest.New(t, "another password")
	gone := piholetest.New(t, piholePassword)
	goneURL := gone.URL
	gone.Close()

	e := newTestEnv(t, withInstances(t, map[string]string{
		secrets.InstanceVar("GOOD"):  piholePassword,
		secrets.InstanceVar("WRONG"): piholePassword,
		secrets.InstanceVar("GONE"):  piholePassword,
	}))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	create := func(name, env, url string) int64 {
		t.Helper()
		in := gen.InstanceInput{Name: name, BaseUrl: url, EnvName: ptr(env)}
		if env != "UNSET" {
			in.Password = ptr(piholePassword) // confirms the variable that is set
		}
		res := c.do(http.MethodPost, "/api/v1/instances", in)
		mustStatus(t, res, http.StatusCreated)
		return decode[gen.Instance](t, res).Id
	}
	goodID := create("good", "GOOD", good.URL)
	wrongID := create("wrong", "WRONG", wrong.URL)
	goneID := create("gone", "GONE", goneURL)
	unsetID := create("unset", "UNSET", good.URL)

	t.Run("validation", func(t *testing.T) {
		res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "x", BaseUrl: "pi.hole", EnvName: ptr("X")})
		mustStatus(t, res, http.StatusBadRequest)
		if res.errorCode() != "validation_failed" || errorDetails(t, res)["field"] != "base_url" {
			t.Errorf("%s", res.Body)
		}
	})
	t.Run("duplicate name", func(t *testing.T) {
		res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "GOOD", BaseUrl: good.URL, EnvName: ptr("OTHER")})
		mustStatus(t, res, http.StatusConflict)
		if res.errorCode() != "conflict" {
			t.Errorf("%s", res.Body)
		}
	})
	t.Run("malformed id", func(t *testing.T) {
		res := c.do(http.MethodGet, "/api/v1/instances/abc", nil)
		mustStatus(t, res, http.StatusBadRequest)
		if res.errorCode() != "validation_failed" {
			t.Errorf("%s", res.Body)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		for _, r := range []struct{ method, suffix string }{
			{http.MethodGet, ""}, {http.MethodDelete, ""}, {http.MethodPost, "/enable"}, {http.MethodPost, "/test"},
		} {
			res := c.do(r.method, instancePath(999, r.suffix), nil)
			if res.Code != http.StatusNotFound || res.errorCode() != "not_found" {
				t.Errorf("%s %s: %d %s", r.method, r.suffix, res.Code, res.Body)
			}
		}
	})

	t.Run("enable refused", func(t *testing.T) {
		tests := []struct {
			id     int64
			status int
			code   string
		}{
			{wrongID, http.StatusBadGateway, "pihole_auth_rejected"},
			{goneID, http.StatusBadGateway, "pihole_unreachable"},
			{unsetID, http.StatusConflict, "instance_password_missing"},
		}
		for _, tt := range tests {
			res := c.do(http.MethodPost, instancePath(tt.id, "/enable"), nil)
			if res.Code != tt.status || res.errorCode() != tt.code {
				t.Errorf("instance %d: %d %s, want %d %s", tt.id, res.Code, res.Body, tt.status, tt.code)
				continue
			}
			if d := errorDetails(t, res); d["instance"] == nil || d["detail"] == nil {
				t.Errorf("details %v", d)
			}
		}
	})

	t.Run("edit of an enabled instance refused", func(t *testing.T) {
		mustStatus(t, c.do(http.MethodPost, instancePath(goodID, "/enable"), nil), http.StatusOK)
		res := c.do(http.MethodPut, instancePath(goodID, ""), gen.InstanceInput{Name: "good", BaseUrl: goneURL, EnvName: ptr("GOOD"), Password: ptr(piholePassword)})
		if res.Code != http.StatusBadGateway || res.errorCode() != "pihole_unreachable" {
			t.Errorf("%d %s", res.Code, res.Body)
		}
	})

	t.Run("failed test is a result", func(t *testing.T) {
		tests := map[int64]string{wrongID: "pihole_auth_rejected", goneID: "pihole_unreachable", unsetID: "instance_password_missing"}
		for id, code := range tests {
			res := c.do(http.MethodPost, instancePath(id, "/test"), nil)
			mustStatus(t, res, http.StatusOK)
			tr := decode[gen.InstanceTestResult](t, res)
			if tr.Ok || tr.Error == nil || string(tr.Error.Code) != code || tr.Error.Message == "" || tr.Error.Detail == nil {
				t.Errorf("instance %d: %s", id, res.Body)
			}
			if strings.Contains(res.Body.String(), piholePassword) {
				t.Errorf("the response contains the password: %s", res.Body)
			}
		}
	})

	t.Run("delete refused while in use", func(t *testing.T) {
		ctx := context.Background()
		if err := e.st.WithTx(ctx, func(q *db.Queries) error {
			role, err := q.CreateRole(ctx, db.CreateRoleParams{Name: "lab staff", CreatedAt: 1})
			if err != nil {
				return err
			}
			return q.InsertGrant(ctx, db.InsertGrantParams{RoleID: role, Permission: "domains.view", ScopeType: "instance",
				InstanceID: sql.NullInt64{Int64: wrongID, Valid: true}})
		}); err != nil {
			t.Fatal(err)
		}
		res := c.do(http.MethodDelete, instancePath(wrongID, ""), nil)
		mustStatus(t, res, http.StatusConflict)
		if roles, _ := errorDetails(t, res)["roles"].([]any); len(roles) != 1 || roles[0] != "lab staff" {
			t.Errorf("%s", res.Body)
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestInstanceRoutesNeedInstancesManage: managing instances needs instances.manage; refused writes are audited and
// never reach a Pi-hole.
func TestInstanceRoutesNeedInstancesManage(t *testing.T) {
	ph := piholetest.New(t, piholePassword)
	e := newTestEnv(t, withInstances(t, map[string]string{secrets.InstanceVar("PIHOLE1"): piholePassword}))
	e.addUser("admin", "admin-password-1", true)
	e.addRoleUser("reader", "reader-password-1", rbac.DomainsView)
	admin := e.loggedIn("admin", "admin-password-1")
	res := admin.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "pihole1", BaseUrl: ph.URL, EnvName: ptr("PIHOLE1"), Password: ptr(piholePassword)})
	mustStatus(t, res, http.StatusCreated)
	id := decode[gen.Instance](t, res).Id
	reader := e.loggedIn("reader", "reader-password-1")

	input := gen.InstanceInput{Name: "x", BaseUrl: ph.URL, EnvName: ptr("PIHOLE1")}
	tests := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/v1/instances", nil},
		{http.MethodPost, "/api/v1/instances", input},
		{http.MethodGet, instancePath(id, ""), nil},
		{http.MethodPut, instancePath(id, ""), input},
		{http.MethodDelete, instancePath(id, ""), nil},
		{http.MethodPost, instancePath(id, "/test"), nil},
		{http.MethodPost, instancePath(id, "/enable"), nil},
		{http.MethodPost, instancePath(id, "/disable"), nil},
	}
	for _, tt := range tests {
		before := len(e.auditRows())
		res := reader.do(tt.method, tt.path, tt.body)
		if res.Code != http.StatusForbidden || res.errorCode() != "forbidden" {
			t.Errorf("%s %s: %d %s", tt.method, tt.path, res.Code, res.Body)
			continue
		}
		if p := errorDetails(t, res)["permission"]; p != "instances.manage" {
			t.Errorf("%s %s: permission %v", tt.method, tt.path, p)
		}
		added := e.auditRows()[before:]
		if isSafeMethod(tt.method) != (len(added) == 0) {
			t.Errorf("%s %s: %d audit rows", tt.method, tt.path, len(added))
		}
	}
	if ph.Logins() != 0 {
		t.Errorf("a refused request reached Pi-hole (%d logins)", ph.Logins())
	}
}

// TestTargetsFollowPermissions: /targets lists the enabled instances where the user holds any permission.
func TestTargetsFollowPermissions(t *testing.T) {
	ph := piholetest.New(t, piholePassword)
	e := newTestEnv(t, withInstances(t, map[string]string{
		secrets.InstanceVar("ONE"): piholePassword, secrets.InstanceVar("TWO"): piholePassword,
		secrets.InstanceVar("OFF"): piholePassword,
	}))
	e.addUser("admin", "admin-password-1", true)
	admin := e.loggedIn("admin", "admin-password-1")
	ids := map[string]int64{}
	for _, n := range []string{"one", "two", "off"} {
		res := admin.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: n, BaseUrl: ph.URL, EnvName: ptr(strings.ToUpper(n)), Password: ptr(piholePassword)})
		mustStatus(t, res, http.StatusCreated)
		ids[n] = decode[gen.Instance](t, res).Id
		if n != "off" {
			mustStatus(t, admin.do(http.MethodPost, instancePath(ids[n], "/enable"), nil), http.StatusOK)
		}
	}

	e.addRoleUser("reader", "reader-password-1", rbac.DomainsView) // scope all
	addInstanceUser(t, e, "lab", "lab-password-12", ids["two"])    // domains.view on instance two only
	e.addRoleUser("nobody", "nobody-password-1", rbac.AuditView)   // global permissions only

	names := func(c *client) []string {
		tl := decode[gen.TargetList](t, c.do(http.MethodGet, "/api/v1/targets", nil))
		var out []string
		for _, tg := range tl.Targets {
			out = append(out, tg.Name)
		}
		return out
	}
	for _, tt := range []struct {
		user, password string
		want           []string
	}{
		{"admin", "admin-password-1", []string{"one", "two"}},
		{"reader", "reader-password-1", []string{"one", "two"}},
		{"lab", "lab-password-12", []string{"two"}},
		{"nobody", "nobody-password-1", nil},
	} {
		if got := names(e.loggedIn(tt.user, tt.password)); !slices.Equal(got, tt.want) {
			t.Errorf("%s sees %v, want %v", tt.user, got, tt.want)
		}
	}
	mustStatus(t, e.client("10.0.0.9:1").do(http.MethodGet, "/api/v1/targets", nil), http.StatusUnauthorized)
}

// addInstanceUser creates a user whose only role grants domains.view on one instance.
func addInstanceUser(t *testing.T, e *testEnv, name, password string, instanceID int64) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.st.WithTx(ctx, func(q *db.Queries) error {
		role, err := q.CreateRole(ctx, db.CreateRoleParams{Name: name + "-role", CreatedAt: 1})
		if err != nil {
			return err
		}
		if err := q.InsertGrant(ctx, db.InsertGrantParams{RoleID: role, Permission: "domains.view", ScopeType: "instance",
			InstanceID: sql.NullInt64{Int64: instanceID, Valid: true}}); err != nil {
			return err
		}
		u, err := q.CreateLocalUser(ctx, db.CreateLocalUserParams{Username: name, PasswordHash: sql.NullString{String: string(hash), Valid: true}})
		if err != nil {
			return err
		}
		return q.AddUserRole(ctx, db.AddUserRoleParams{UserID: u.ID, RoleID: role})
	}); err != nil {
		t.Fatal(err)
	}
}

// TestReloadRebuildsInstanceClients: a reloaded password file gives that instance a new client, without a restart.
func TestReloadRebuildsInstanceClients(t *testing.T) {
	ph := piholetest.New(t, "new password")
	pwFile := filepath.Join(t.TempDir(), "pihole1")
	if err := os.WriteFile(pwFile, []byte("old password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newTestEnv(t, withInstances(t, map[string]string{secrets.InstanceVar("PIHOLE1") + "_FILE": pwFile}))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")
	res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "pihole1", BaseUrl: ph.URL, EnvName: ptr("PIHOLE1"), Password: ptr("old password")})
	mustStatus(t, res, http.StatusCreated)
	id := decode[gen.Instance](t, res).Id
	if res := c.do(http.MethodPost, instancePath(id, "/enable"), nil); res.errorCode() != "pihole_auth_rejected" {
		t.Fatalf("enable with the old password: %d %s", res.Code, res.Body)
	}

	if err := os.WriteFile(pwFile, []byte("new password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, c.do(http.MethodPost, "/api/v1/system/reload", struct{}{}), http.StatusOK)
	mustStatus(t, c.do(http.MethodPost, instancePath(id, "/enable"), nil), http.StatusOK)

	// Change it again now the instance is in the pool: the reload rebuilds its client and says so in the audit log.
	if err := os.WriteFile(pwFile, []byte("newer password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, c.do(http.MethodPost, "/api/v1/system/reload", struct{}{}), http.StatusOK)
	rows := e.auditRows()
	last := rows[len(rows)-1]
	var d map[string]any
	if err := json.Unmarshal([]byte(last.Detail), &d); err != nil {
		t.Fatal(err)
	}
	if rebuilt, _ := d["instances_rebuilt"].([]any); last.Action != audit.ActionConfigReload || len(rebuilt) != 1 || rebuilt[0] != "pihole1" {
		t.Errorf("audit row %s %s", last.Action, last.Detail)
	}
}

func TestInstanceStoredPassword(t *testing.T) {
	ph := piholetest.New(t, piholePassword)
	e := newTestEnv(t, withInstances(t, map[string]string{
		secrets.VarSecretKey:           secrets.NewKey(),
		secrets.InstanceVar("PIHOLE1"): piholePassword,
	}))
	e.addUser("admin", "admin-password-1", true)
	c := e.loggedIn("admin", "admin-password-1")

	if list := decode[gen.InstanceList](t, c.do(http.MethodGet, "/api/v1/instances", nil)); !list.CanStorePasswords {
		t.Error("can_store_passwords is false with a master key")
	}

	res := c.do(http.MethodPost, "/api/v1/instances", gen.InstanceInput{Name: "kitchen", BaseUrl: ph.URL, Password: ptr("first password")})
	mustStatus(t, res, http.StatusCreated)
	if strings.Contains(res.Body.String(), "first password") {
		t.Fatalf("the password is in the response: %s", res.Body)
	}
	inst := decode[gen.Instance](t, res)
	if inst.PasswordSource != gen.InstancePasswordSource("stored") || !inst.PasswordSet || inst.EnvName != nil || inst.PasswordVariable != nil ||
		inst.PasswordUpdatedBy == nil || *inst.PasswordUpdatedBy != "admin" || inst.PasswordUpdatedAt == nil {
		t.Fatalf("created %s", res.Body)
	}

	// Rotating it: a wrong one is still saved while the instance is disabled; the right one lets it be enabled.
	mustStatus(t, c.do(http.MethodPut, instancePath(inst.Id, "/password"), gen.InstancePassword{Password: ptr(piholePassword)}), http.StatusOK)
	mustStatus(t, c.do(http.MethodPost, instancePath(inst.Id, "/enable"), nil), http.StatusOK)
	res = c.do(http.MethodPut, instancePath(inst.Id, "/password"), gen.InstancePassword{Password: ptr("typo")})
	if res.Code != http.StatusBadGateway || res.errorCode() != "pihole_auth_rejected" {
		t.Errorf("a refused password on an enabled instance: %d %s", res.Code, res.Body)
	}

	res = c.do(http.MethodPut, instancePath(inst.Id, ""), gen.InstanceInput{Name: "kitchen", BaseUrl: "http://127.0.0.1:1"})
	if res.Code != http.StatusBadRequest || errorDetails(t, res)["field"] != "password" {
		t.Errorf("a new address without the password: %d %s", res.Code, res.Body)
	}

	envInst := decode[gen.Instance](t, c.do(http.MethodPost, "/api/v1/instances",
		gen.InstanceInput{Name: "env", BaseUrl: ph.URL, EnvName: ptr("PIHOLE1"), Password: ptr(piholePassword)}))
	if envInst.PasswordSource != gen.InstancePasswordSource("environment") || envInst.PasswordUpdatedAt != nil {
		t.Errorf("env instance %+v", envInst)
	}
	res = c.do(http.MethodPut, instancePath(envInst.Id, "/password"), gen.InstancePassword{Password: ptr("x")})
	if res.Code != http.StatusConflict || res.errorCode() != "conflict" {
		t.Errorf("storing over a variable: %d %s", res.Code, res.Body)
	}
	if res := c.do(http.MethodPut, instancePath(envInst.Id, "/password"), map[string]any{}); res.Code != http.StatusBadRequest {
		t.Errorf("no password: %d %s", res.Code, res.Body)
	}

	for _, line := range e.auditLines() {
		if strings.Contains(line, piholePassword) || strings.Contains(line, "first password") || strings.Contains(line, "typo") {
			t.Errorf("a password reached the audit log: %s", line)
		}
	}
}
