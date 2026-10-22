// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testEnv is a fake environment. Load and Reload read it through Options.Getenv/Environ.
type testEnv map[string]string

func (e testEnv) getenv(k string) string { return e[k] }
func (e testEnv) environ() []string {
	var out []string
	for k, v := range e {
		out = append(out, k+"="+v)
	}
	return out
}

func load(t *testing.T, env testEnv) (*Manager, error) {
	t.Helper()
	return Load(Options{DataDir: t.TempDir(), Getenv: env.getenv, Environ: env.environ})
}

func mustLoad(t *testing.T, env testEnv) *Manager {
	t.Helper()
	m, err := load(t, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, KeySize)) }

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "lf"), "hunter2\n")
	writeFile(t, filepath.Join(dir, "crlf"), "hunter2\r\n")
	writeFile(t, filepath.Join(dir, "inner-space"), "  pass word  \n")
	writeFile(t, filepath.Join(dir, "empty"), "\n")
	writeFile(t, filepath.Join(dir, "big"), strings.Repeat("x", maxFileSize+1))

	tests := []struct {
		name    string
		env     testEnv
		want    string
		source  Source
		wantErr string
	}{
		{name: "unset", env: testEnv{}, source: SourceUnset},
		{name: "env", env: testEnv{"X": "hunter2"}, want: "hunter2", source: SourceEnv},
		{name: "file lf", env: testEnv{"X_FILE": filepath.Join(dir, "lf")}, want: "hunter2", source: SourceFile},
		{name: "file crlf", env: testEnv{"X_FILE": filepath.Join(dir, "crlf")}, want: "hunter2", source: SourceFile},
		{name: "file keeps spaces", env: testEnv{"X_FILE": filepath.Join(dir, "inner-space")}, want: "  pass word  ", source: SourceFile},
		{name: "both set", env: testEnv{"X": "a", "X_FILE": filepath.Join(dir, "lf")}, wantErr: "both set"},
		{name: "missing file", env: testEnv{"X_FILE": filepath.Join(dir, "nope")}, wantErr: "X_FILE"},
		{name: "empty file", env: testEnv{"X_FILE": filepath.Join(dir, "empty")}, wantErr: "is empty"},
		{name: "oversized file", env: testEnv{"X_FILE": filepath.Join(dir, "big")}, wantErr: "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, src, _, err := lookup(tt.env.getenv, "X")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.Reveal() != tt.want || src != tt.source {
				t.Fatalf("got %q from %q, want %q from %q", v.Reveal(), src, tt.want, tt.source)
			}
		})
	}
}

func TestLoadErrorsNeverContainValues(t *testing.T) {
	const secret = "s3cr3t-value-that-must-not-leak"
	_, err := load(t, testEnv{
		VarSecretKey:                  secret, // not base64 of 32 bytes
		VarSessionKey:                 secret,
		VarLDAPBindPassword:           secret,
		VarLDAPBindPassword + "_FILE": "/nonexistent",
	})
	if err == nil {
		t.Fatal("Load succeeded with malformed keys")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the secret: %v", err)
	}
	for _, want := range []string{VarSecretKey, VarSessionKey, VarLDAPBindPassword} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error doesn't mention %s: %v", want, err)
		}
	}
}

func TestDecodeKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xfb}, KeySize) // 0xfb makes + and / (or - and _) appear
	tests := []struct {
		name, in string
		ok       bool
	}{
		{"std", base64.StdEncoding.EncodeToString(raw), true},
		{"raw std", base64.RawStdEncoding.EncodeToString(raw), true},
		{"url", base64.URLEncoding.EncodeToString(raw), true},
		{"raw url", base64.RawURLEncoding.EncodeToString(raw), true},
		{"trailing newline", base64.StdEncoding.EncodeToString(raw) + "\n", true},
		{"too short", base64.StdEncoding.EncodeToString(raw[:16]), false},
		{"not base64", "this is not a key!", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := DecodeKey(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if tt.ok && !bytes.Equal(k, raw) {
				t.Fatal("decoded key differs")
			}
		})
	}
}

func TestMasterKey(t *testing.T) {
	if m := mustLoad(t, testEnv{}); m.Cipher() != nil {
		t.Fatal("Cipher() non-nil without a master key")
	}
	m := mustLoad(t, testEnv{VarSecretKey: key(1)})
	if m.Cipher() == nil {
		t.Fatal("Cipher() nil with a master key")
	}
	if _, err := load(t, testEnv{VarSecretKey: "short"}); err == nil {
		t.Fatal("malformed master key accepted")
	}
}

func TestSessionKey(t *testing.T) {
	t.Run("generated once and reused", func(t *testing.T) {
		dir := t.TempDir()
		env := testEnv{}
		m1, err := Load(Options{DataDir: dir, Getenv: env.getenv, Environ: env.environ})
		if err != nil {
			t.Fatal(err)
		}
		k1 := m1.SessionKey()
		if len(k1.RevealBytes()) != KeySize {
			t.Fatalf("session key is %d bytes", len(k1.RevealBytes()))
		}
		if st := find(m1.Status(), VarSessionKey); st.Source != SourceGenerated || !st.Set {
			t.Fatalf("status = %+v", st)
		}
		m2, err := Load(Options{DataDir: dir, Getenv: env.getenv, Environ: env.environ})
		if err != nil {
			t.Fatal(err)
		}
		if !m2.SessionKey().Equal(k1) {
			t.Fatal("session key changed across loads")
		}
	})
	t.Run("created in missing data dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b")
		env := testEnv{}
		if _, err := Load(Options{DataDir: dir, Getenv: env.getenv, Environ: env.environ}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, SessionKeyFile)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("env override", func(t *testing.T) {
		dir := t.TempDir()
		env := testEnv{VarSessionKey: key(7)}
		m, err := Load(Options{DataDir: dir, Getenv: env.getenv, Environ: env.environ})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(m.SessionKey().RevealBytes(), bytes.Repeat([]byte{7}, KeySize)) {
			t.Fatal("override not used")
		}
		if _, err := os.Stat(filepath.Join(dir, SessionKeyFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("session.key written despite override: %v", err)
		}
	})
	t.Run("malformed file is an error, not overwritten", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, SessionKeyFile)
		writeFile(t, path, "garbage\n")
		env := testEnv{}
		if _, err := Load(Options{DataDir: dir, Getenv: env.getenv, Environ: env.environ}); err == nil {
			t.Fatal("malformed session.key accepted")
		}
		if b, _ := os.ReadFile(path); string(b) != "garbage\n" {
			t.Fatal("malformed session.key was overwritten")
		}
	})
}

func TestInstanceDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "p2"), "two\n")
	m := mustLoad(t, testEnv{
		"PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD":      "one",
		"PIHOLE_RBAC_INSTANCE_PIHOLE2_PASSWORD_FILE": filepath.Join(dir, "p2"),
		"PIHOLE_RBAC_INSTANCE_EMPTY_PASSWORD":        "",
		"PIHOLE_RBAC_INSTANCE_X_TIMEOUT":             "5", // not a password variable
		"PIHOLE_RBAC_INSTANCE__PASSWORD":             "no name",
	})
	for envName, want := range map[string]string{"PIHOLE1": "one", "PIHOLE2": "two"} {
		v, ok := m.InstancePassword(envName)
		if !ok || v.Reveal() != want {
			t.Errorf("InstancePassword(%s) = %q, %v", envName, v.Reveal(), ok)
		}
	}
	if _, ok := m.InstancePassword("EMPTY"); ok {
		t.Error("empty variable reported as set")
	}
	if _, ok := m.InstancePassword("PIHOLE3"); ok {
		t.Error("unknown instance reported as set")
	}
	var names []string
	for _, s := range m.Status() {
		names = append(names, s.Name)
	}
	want := []string{VarSecretKey, VarSessionKey, VarLDAPBindPassword,
		"PIHOLE_RBAC_INSTANCE_EMPTY_PASSWORD", "PIHOLE_RBAC_INSTANCE_PIHOLE1_PASSWORD", "PIHOLE_RBAC_INSTANCE_PIHOLE2_PASSWORD"}
	if !slices.Equal(names, want) {
		t.Fatalf("Status names = %v, want %v", names, want)
	}

	if _, err := load(t, testEnv{"PIHOLE_RBAC_INSTANCE_pihole1_PASSWORD": "x"}); err == nil {
		t.Fatal("lowercase instance name accepted")
	}
}

func TestStatusNeverHoldsValues(t *testing.T) {
	m := mustLoad(t, testEnv{VarLDAPBindPassword: "hunter2", VarSecretKey: key(3)})
	b, err := json.Marshal(m.Status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), key(3)) {
		t.Fatalf("status JSON contains a secret: %s", b)
	}
	if st := find(m.Status(), VarLDAPBindPassword); !st.Set || st.Source != SourceEnv {
		t.Fatalf("status = %+v", st)
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	ldap := filepath.Join(dir, "ldap")
	inst := filepath.Join(dir, "inst")
	master := filepath.Join(dir, "master")
	writeFile(t, ldap, "ldap-1\n")
	writeFile(t, inst, "inst-1\n")
	writeFile(t, master, key(1)+"\n")
	m := mustLoad(t, testEnv{
		VarLDAPBindPassword + "_FILE":          ldap,
		VarSecretKey + "_FILE":                 master,
		"PIHOLE_RBAC_INSTANCE_A_PASSWORD_FILE": inst,
		"PIHOLE_RBAC_INSTANCE_B_PASSWORD":      "plain-env",
	})
	oldCipher := m.Cipher()

	t.Run("nothing changed", func(t *testing.T) {
		if res := m.Reload(); len(res.Changed) != 0 || len(res.Failed) != 0 {
			t.Fatalf("Reload = %+v", res)
		}
	})

	t.Run("changed files are picked up", func(t *testing.T) {
		writeFile(t, ldap, "ldap-2\n")
		writeFile(t, master, key(2)+"\n")
		res := m.Reload()
		if !sameSet(res.Changed, []string{VarLDAPBindPassword, VarSecretKey}) || len(res.Failed) != 0 {
			t.Fatalf("Changed = %v", res.Changed)
		}
		if v, _ := m.LDAPBindPassword(); v.Reveal() != "ldap-2" {
			t.Fatalf("LDAP password = %q", v.Reveal())
		}
		if m.Cipher().KeyID() == oldCipher.KeyID() {
			t.Fatal("cipher not replaced")
		}
	})

	t.Run("failed reload keeps previous value", func(t *testing.T) {
		writeFile(t, inst, "") // empty file is an error
		writeFile(t, master, "not-a-key\n")
		before := m.Cipher()
		res := m.Reload()
		if len(res.Changed) != 0 {
			t.Fatalf("Changed = %v", res.Changed)
		}
		var failed []string
		for _, f := range res.Failed {
			failed = append(failed, f.Name)
		}
		if !sameSet(failed, []string{"PIHOLE_RBAC_INSTANCE_A_PASSWORD", VarSecretKey}) {
			t.Fatalf("Failed = %v", res.Failed)
		}
		if v, _ := m.InstancePassword("A"); v.Reveal() != "inst-1" {
			t.Fatalf("instance password = %q, want previous value", v.Reveal())
		}
		if m.Cipher() != before {
			t.Fatal("cipher replaced by a malformed key")
		}
	})

	t.Run("plain env vars are not reloaded", func(t *testing.T) {
		if v, _ := m.InstancePassword("B"); v.Reveal() != "plain-env" {
			t.Fatalf("B = %q", v.Reveal())
		}
	})
}

func TestCipher(t *testing.T) {
	c1, err := NewCipher(bytes.Repeat([]byte{1}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := NewCipher(bytes.Repeat([]byte{2}, KeySize))
	if c1.KeyID() == c2.KeyID() || len(c1.KeyID()) != 16 {
		t.Fatalf("key IDs %q %q", c1.KeyID(), c2.KeyID())
	}
	if _, err := NewCipher(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}

	secret := NewValue([]byte("https://discord.com/api/webhooks/1/abc"))
	aad := AAD("notification_channels", 3)
	s, err := c1.Seal(secret, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nonce) != 12 || s.KeyID != c1.KeyID() || bytes.Contains(s.Ciphertext, secret.RevealBytes()) {
		t.Fatalf("sealed = %+v", s)
	}
	s2, _ := c1.Seal(secret, aad)
	if bytes.Equal(s.Nonce, s2.Nonce) {
		t.Fatal("nonce reused")
	}

	got, err := c1.Open(s, aad)
	if err != nil || !got.Equal(secret) {
		t.Fatalf("Open = %v, %v", got.Reveal(), err)
	}

	tampered := s
	tampered.Ciphertext = append([]byte(nil), s.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	badNonce := s
	badNonce.Nonce = s.Nonce[:8]
	tests := []struct {
		name string
		c    *Cipher
		s    Sealed
		aad  []byte
		want error
	}{
		{"other row", c1, s, AAD("notification_channels", 4), ErrDecrypt},
		{"tampered", c1, tampered, aad, ErrDecrypt},
		{"short nonce", c1, badNonce, aad, ErrDecrypt},
		{"other key", c2, s, aad, ErrWrongKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.c.Open(tt.s, tt.aad); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValueRedaction(t *testing.T) {
	const s = "hunter2"
	v := NewValue([]byte(s))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		if out := fmt.Sprintf(verb, v); strings.Contains(out, s) || strings.Contains(out, fmt.Sprintf("%x", s)) {
			t.Errorf("%s leaks: %s", verb, out)
		}
	}
	// Inside a struct, fmt and json still go through Value's methods.
	type wrapper struct{ Password Value }
	if out := fmt.Sprintf("%+v", wrapper{v}); strings.Contains(out, s) {
		t.Errorf("struct %%+v leaks: %s", out)
	}
	b, _ := json.Marshal(wrapper{v})
	if strings.Contains(string(b), s) {
		t.Errorf("json leaks: %s", b)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "password", v, "group", slog.GroupValue(slog.Any("p", v)))
	if strings.Contains(buf.String(), s) {
		t.Errorf("slog leaks: %s", buf.String())
	}
	if v.Reveal() != s {
		t.Fatal("Reveal lost the value")
	}
}

func find(sts []Status, name string) Status {
	for _, s := range sts {
		if s.Name == name {
			return s
		}
	}
	return Status{}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestChannelOverrideDiscovery(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "ops"), "https://discord.com/api/webhooks/2/def\n")
	m := mustLoad(t, testEnv{
		"PIHOLE_RBAC_NOTIFY_ALERTS_SECRET":   "https://discord.com/api/webhooks/1/abc",
		"PIHOLE_RBAC_NOTIFY_OPS_SECRET_FILE": filepath.Join(dir, "ops"),
		"PIHOLE_RBAC_NOTIFY_X_TIMEOUT":       "5", // not a secret variable
	})
	for envName, want := range map[string]string{
		"ALERTS": "https://discord.com/api/webhooks/1/abc",
		"OPS":    "https://discord.com/api/webhooks/2/def",
	} {
		v, ok := m.ChannelSecret(envName)
		if !ok || v.Reveal() != want {
			t.Errorf("ChannelSecret(%s) = %q, %v", envName, v.Reveal(), ok)
		}
	}
	if _, ok := m.ChannelSecret("OTHER"); ok {
		t.Error("unknown channel reported as set")
	}
	if st := find(m.Status(), ChannelVar("OPS")); !st.Set || st.Source != SourceFile {
		t.Fatalf("status = %+v", st)
	}

	writeFile(t, filepath.Join(dir, "ops"), "https://discord.com/api/webhooks/3/ghi\n")
	if res := m.Reload(); !slices.Equal(res.Changed, []string{ChannelVar("OPS")}) {
		t.Fatalf("Reload = %+v", res)
	}

	if _, err := load(t, testEnv{"PIHOLE_RBAC_NOTIFY_alerts_SECRET": "x"}); err == nil || !strings.Contains(err.Error(), "notification channel") {
		t.Fatalf("lowercase channel name: err = %v", err)
	}
}
