// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package instances

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

func value(s string) *secrets.Value {
	v := secrets.NewValue([]byte(s))
	return &v
}

// withMasterKey gives the env a master key, so passwords can be stored.
func (e *svcEnv) withMasterKey() *secrets.Cipher {
	e.t.Helper()
	c, err := secrets.NewCipher(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		e.t.Fatal(err)
	}
	e.pw.mu.Lock()
	e.pw.cipher = c
	e.pw.mu.Unlock()
	return c
}

func TestStoredPassword(t *testing.T) {
	e := newSvcEnv(t)
	c := e.withMasterKey()
	ph := piholetest.New(t, password)

	inst, err := e.svc.Create(e.ctx, e.admin, Input{Name: "stored", BaseURL: ph.URL, Password: value(password)})
	if err != nil {
		t.Fatal(err)
	}
	if inst.EnvName != "" || inst.Password.IsZero() || inst.Password.UpdatedBy != "alice" || !inst.Password.UpdatedAt.Equal(t0) {
		t.Fatalf("created %+v", inst)
	}
	if got, _ := e.svc.Get(e.ctx, inst.ID); !got.equal(inst) || e.pool.PasswordSource(got) != SourceStored {
		t.Fatalf("read back %+v", got)
	}
	// Only ciphertext reaches the database.
	row, _ := e.st.Read().GetInstance(e.ctx, inst.ID)
	if bytes.Contains(row.PasswordCiphertext, []byte(password)) || row.PasswordKeyID.String != c.KeyID() {
		t.Errorf("stored row %+v", row)
	}
	if d := detail(t, e.lastAudit()); d["password"] != "stored" {
		t.Errorf("audit detail %v", d)
	}

	if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
		t.Fatalf("enable with a stored password: %v", err)
	}
	if err := e.pool.Do(e.ctx, inst.ID, status); err != nil {
		t.Errorf("pool with a stored password: %v", err)
	}

	t.Run("a variable overrides the stored password", func(t *testing.T) {
		e.pw.set("STORED", "from the environment")
		defer e.pw.set("STORED", "")
		over := inst
		over.EnvName = "STORED"
		if got, err := e.pool.password(over); err != nil || got.Reveal() != "from the environment" || e.pool.PasswordSource(over) != SourceEnvironment {
			t.Errorf("password %v %v, source %s", got, err, e.pool.PasswordSource(over))
		}
	})

	t.Run("the ciphertext only opens on its own row", func(t *testing.T) {
		moved := inst
		moved.ID = inst.ID + 100
		if _, err := e.pool.password(moved); !errors.Is(err, ErrMisconfigured) {
			t.Errorf("err = %v, want ErrMisconfigured", err)
		}
	})

	t.Run("without the master key it can't be read", func(t *testing.T) {
		e.pw.mu.Lock()
		e.pw.cipher = nil
		e.pw.mu.Unlock()
		defer e.withMasterKey()
		if _, err := e.pool.password(inst); !errors.Is(err, ErrMisconfigured) || Kind(err) != CodeMisconfigured {
			t.Errorf("err = %v", err)
		}
	})
}

func TestSetPassword(t *testing.T) {
	e := newSvcEnv(t)
	e.withMasterKey()
	ph := piholetest.New(t, "new password")
	inst, err := e.svc.Create(e.ctx, e.admin, Input{Name: "rotated", BaseURL: ph.URL, Password: value("old password")})
	if err != nil {
		t.Fatal(err)
	}

	// A disabled instance takes a password without testing it.
	e.svc.Now = func() time.Time { return t0.Add(time.Hour) }
	got, err := e.svc.SetPassword(e.ctx, e.admin, inst.ID, *value("still wrong"))
	if err != nil || !got.Password.UpdatedAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("SetPassword on a disabled instance: %+v, %v", got, err)
	}
	if row := e.lastAudit(); row.Action != audit.ActionInstancePassword || strings.Contains(row.Detail, "still wrong") {
		t.Errorf("audit row %+v", row)
	}

	// An enabled one is tested first, and a password the Pi-hole refuses changes nothing.
	if _, err := e.svc.SetPassword(e.ctx, e.admin, inst.ID, *value("new password")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetEnabled(e.ctx, e.admin, inst.ID, true); err != nil {
		t.Fatal(err)
	}
	before, _ := e.svc.Get(e.ctx, inst.ID)
	_, err = e.svc.SetPassword(e.ctx, e.admin, inst.ID, *value("typo"))
	var te *TestError
	if !errors.As(err, &te) || Kind(err) != "pihole_auth_rejected" {
		t.Fatalf("err = %v, want a refused test", err)
	}
	if after, _ := e.svc.Get(e.ctx, inst.ID); !after.equal(before) {
		t.Error("a refused password was stored")
	}
	if err := e.pool.Do(e.ctx, inst.ID, status); err != nil {
		t.Errorf("pool after a refused rotation: %v", err)
	}

	t.Run("refused", func(t *testing.T) {
		_, err := e.svc.SetPassword(e.ctx, e.viewer, inst.ID, *value("x"))
		wantCode(t, err, rbac.CodeForbidden, "")
		_, err = e.svc.SetPassword(e.ctx, e.admin, inst.ID, secrets.Value{})
		wantCode(t, err, rbac.CodeValidation, "password")
		_, err = e.svc.SetPassword(e.ctx, e.admin, 999, *value("x"))
		wantCode(t, err, rbac.CodeNotFound, "")

		envInst := e.create("env", "PIHOLE1", ph.URL)
		_, err = e.svc.SetPassword(e.ctx, e.admin, envInst.ID, *value("x"))
		wantCode(t, err, rbac.CodeConflict, "password")

		e.pw.mu.Lock()
		e.pw.cipher = nil
		e.pw.mu.Unlock()
		defer e.withMasterKey()
		_, err = e.svc.SetPassword(e.ctx, e.admin, inst.ID, *value("x"))
		wantCode(t, err, rbac.CodeConflict, "password")
		_, err = e.svc.Create(e.ctx, e.admin, Input{Name: "nokey", BaseURL: ph.URL, Password: value("x")})
		wantCode(t, err, rbac.CodeValidation, "password")
	})
}

// TestPasswordOnlyGoesWhereConfirmed: a password is never sent to an address nobody confirmed it for.
func TestPasswordOnlyGoesWhereConfirmed(t *testing.T) {
	e := newSvcEnv(t)
	e.withMasterKey()
	real := piholetest.New(t, password)
	evil := piholetest.New(t, "anything")

	t.Run("a new address needs the stored password again", func(t *testing.T) {
		inst, err := e.svc.Create(e.ctx, e.admin, Input{Name: "a", BaseURL: real.URL, Password: value(password)})
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*Input){
			func(in *Input) { in.BaseURL = evil.URL },
			func(in *Input) { in.TLSMode = "insecure" },
		} {
			in := Input{Name: "a", BaseURL: real.URL}
			change(&in)
			_, err := e.svc.Update(e.ctx, e.admin, inst.ID, in)
			wantCode(t, err, rbac.CodeValidation, "password")
		}
		if evil.Logins() != 0 {
			t.Fatal("the stored password was sent to the new address")
		}
		// With a password, it replaces the stored one.
		got, err := e.svc.Update(e.ctx, e.admin, inst.ID, Input{Name: "a", BaseURL: evil.URL, Password: value("anything")})
		if err != nil || got.BaseURL != evil.URL {
			t.Fatalf("Update with a password: %+v, %v", got, err)
		}
		if pw, _ := e.pool.password(got); pw.Reveal() != "anything" {
			t.Error("the new password wasn't stored")
		}
	})

	t.Run("an instance without a password can move freely", func(t *testing.T) {
		inst := e.create("b", "", real.URL)
		if _, err := e.svc.Update(e.ctx, e.admin, inst.ID, Input{Name: "b", BaseURL: evil.URL}); err != nil {
			t.Error(err)
		}
	})

	t.Run("a variable that is set must be confirmed", func(t *testing.T) {
		// Re-adding an instance under an existing variable's name, at another address.
		_, err := e.svc.Create(e.ctx, e.admin, Input{Name: "c", BaseURL: evil.URL, EnvName: "PIHOLE2"})
		wantCode(t, err, rbac.CodeValidation, "password")
		_, err = e.svc.Create(e.ctx, e.admin, Input{Name: "c", BaseURL: evil.URL, EnvName: "PIHOLE2", Password: value("guess")})
		wantCode(t, err, rbac.CodeValidation, "password")

		// Switching an existing instance to it.
		inst := e.create("d", "", evil.URL)
		_, err = e.svc.Update(e.ctx, e.admin, inst.ID, Input{Name: "d", BaseURL: evil.URL, EnvName: "PIHOLE2"})
		wantCode(t, err, rbac.CodeValidation, "password")

		// Moving an instance that uses one.
		envInst := e.create("e", "PIHOLE1", real.URL)
		_, err = e.svc.Update(e.ctx, e.admin, envInst.ID, Input{Name: "e", BaseURL: evil.URL, EnvName: "PIHOLE1"})
		wantCode(t, err, rbac.CodeValidation, "password")

		// Knowing the password is enough, and it isn't stored: the variable stays the source.
		got, err := e.svc.Update(e.ctx, e.admin, envInst.ID, Input{Name: "e", BaseURL: evil.URL, EnvName: "PIHOLE1", Password: value(password)})
		if err != nil || !got.Password.IsZero() || e.pool.PasswordSource(got) != SourceEnvironment {
			t.Errorf("confirmed move: %+v, %v", got, err)
		}
		if evil.Logins() != 0 {
			t.Error("a password reached the other address while disabled")
		}
	})

}
