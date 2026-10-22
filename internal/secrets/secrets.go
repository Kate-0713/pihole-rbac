// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secrets loads the tier 1 secrets (the master key, session key, LDAP bind password, Pi-hole instance
// passwords and any notification channel secrets overridden by the environment) from PIHOLE_RBAC_* environment variables or their *_FILE variants, reloads the file-based ones on
// demand, generates the session key when none is supplied, and encrypts tier 2 secrets (notification credentials)
// with AES-256-GCM under the master key.
//
// Secret values are held as Value, which redacts itself in logs, fmt output and JSON. Nothing in this package logs,
// and no error it returns contains a secret value.
package secrets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Variable names. Each also accepts a _FILE suffix.
const (
	VarSecretKey        = "PIHOLE_RBAC_SECRET_KEY"
	VarSessionKey       = "PIHOLE_RBAC_SESSION_KEY"
	VarLDAPBindPassword = "PIHOLE_RBAC_LDAP_BIND_PASSWORD"

	instancePrefix = "PIHOLE_RBAC_INSTANCE_"
	instanceSuffix = "_PASSWORD"
	channelPrefix  = "PIHOLE_RBAC_NOTIFY_"
	channelSuffix  = "_SECRET"
)

// SessionKeyFile is the generated session key's file name in the data directory.
const SessionKeyFile = "session.key"

// InstanceVar returns the variable that holds the password of the instance whose env_name is envName.
func InstanceVar(envName string) string {
	return instancePrefix + envName + instanceSuffix
}

// ChannelVar returns the variable that overrides the stored secret of the notification channel whose env_name is
// envName. When it is set, the environment value is used instead of the encrypted one in the database.
func ChannelVar(envName string) string {
	return channelPrefix + envName + channelSuffix
}

// ValidEnvName reports whether s is a valid env_name for an instance or notification channel: [A-Z0-9_]+, as the
// database CHECKs require.
func ValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// Options configures Load. Getenv and Environ default to the process environment; tests replace them.
type Options struct {
	DataDir string // where session.key is generated if PIHOLE_RBAC_SESSION_KEY isn't set
	Getenv  func(string) string
	Environ func() []string
}

type entry struct {
	value  Value
	source Source
	path   string // for SourceFile
}

// Manager holds the current tier 1 secrets. It is safe for concurrent use.
type Manager struct {
	getenv  func(string) string
	dataDir string

	mu      sync.RWMutex
	entries map[string]*entry // by variable name, without _FILE
	cipher  *Cipher           // nil when no master key is set
}

// Load reads every tier 1 secret. Any problem is fatal at startup, and every problem is reported, not just the
// first: both NAME and NAME_FILE set, an unreadable or empty file, a malformed key, or an instance or channel
// variable whose name isn't a valid env_name. A missing secret is not an error here; what depends on it reports it as missing.
func Load(opts Options) (*Manager, error) {
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Environ == nil {
		opts.Environ = os.Environ
	}
	if opts.DataDir == "" {
		return nil, errors.New("secrets: data directory not set")
	}
	m := &Manager{getenv: opts.Getenv, dataDir: opts.DataDir, entries: map[string]*entry{}}

	environ := opts.Environ()
	instanceVars, ierr := discover(environ, instancePrefix, instanceSuffix, "instance")
	channelVars, cerr := discover(environ, channelPrefix, channelSuffix, "notification channel")
	errs := []error{ierr, cerr}
	names := append([]string{VarSecretKey, VarSessionKey, VarLDAPBindPassword}, instanceVars...)
	for _, name := range append(names, channelVars...) {
		v, src, path, err := lookup(m.getenv, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m.entries[name] = &entry{value: v, source: src, path: path}
	}

	if e := m.entries[VarSecretKey]; e != nil && !e.value.IsZero() {
		c, err := cipherFrom(e.value)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", VarSecretKey, err))
		}
		m.cipher = c
	}

	if e := m.entries[VarSessionKey]; e != nil && !e.value.IsZero() {
		k, err := DecodeKey(e.value.Reveal())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", VarSessionKey, err))
		}
		e.value = Value{b: k}
	} else if e != nil {
		k, err := loadOrCreateSessionKey(m.dataDir)
		if err != nil {
			errs = append(errs, err)
		}
		m.entries[VarSessionKey] = &entry{value: Value{b: k}, source: SourceGenerated, path: filepath.Join(m.dataDir, SessionKeyFile)}
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return m, nil
}

// discover finds the <prefix><NAME><suffix>[_FILE] variables, such as PIHOLE_RBAC_INSTANCE_<NAME>_PASSWORD. The
// environment can't change after startup, so the set found here is the set a reload can re-read; a new variable
// needs a restart.
func discover(environ []string, prefix, suffix, what string) ([]string, error) {
	var names []string
	var errs []error
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		base := strings.TrimSuffix(k, "_FILE")
		if !strings.HasSuffix(base, suffix) || len(base) <= len(prefix)+len(suffix) {
			continue
		}
		envName := base[len(prefix) : len(base)-len(suffix)]
		if !ValidEnvName(envName) {
			errs = append(errs, fmt.Errorf("%s: %s name %q may only contain A-Z, 0-9 and _", k, what, envName))
			continue
		}
		if !slices.Contains(names, base) {
			names = append(names, base)
		}
	}
	slices.Sort(names)
	return names, errors.Join(errs...)
}

func cipherFrom(v Value) (*Cipher, error) {
	k, err := DecodeKey(v.Reveal())
	if err != nil {
		return nil, err
	}
	return NewCipher(k)
}

// loadOrCreateSessionKey reads $DATA_DIR/session.key, generating it (mode 0600) on first run. A malformed file is an
// error, not something to overwrite silently.
func loadOrCreateSessionKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, SessionKeyFile)
	for range 2 {
		b, err := os.ReadFile(path)
		if err == nil {
			k, err := DecodeKey(string(b))
			if err != nil {
				return nil, fmt.Errorf("%s: %w (delete the file to generate a new key; that signs everyone out)", path, err)
			}
			return k, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue // created between our read and open; read it
		}
		if err != nil {
			return nil, err
		}
		key := randomBytes(KeySize)
		_, werr := f.WriteString(encodeKey(key) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path)
			return nil, fmt.Errorf("write %s: %w", path, werr)
		}
		return key, nil
	}
	return nil, fmt.Errorf("%s: could not read or create", path)
}

// Cipher returns the tier 2 cipher, or nil if no master key is set (tier 2 secrets are then disabled).
func (m *Manager) Cipher() *Cipher {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cipher
}

// SessionKey returns the key for signing session cookies and CSRF tokens. It is always set after Load.
func (m *Manager) SessionKey() Value {
	return m.get(VarSessionKey)
}

// LDAPBindPassword returns the LDAP service account password, and whether it is set.
func (m *Manager) LDAPBindPassword() (Value, bool) {
	v := m.get(VarLDAPBindPassword)
	return v, !v.IsZero()
}

// InstancePassword returns the password for the instance whose env_name is envName, and whether it is set.
func (m *Manager) InstancePassword(envName string) (Value, bool) {
	v := m.get(InstanceVar(envName))
	return v, !v.IsZero()
}

// ChannelSecret returns the environment override for the notification channel whose env_name is envName, and
// whether it is set.
func (m *Manager) ChannelSecret(envName string) (Value, bool) {
	v := m.get(ChannelVar(envName))
	return v, !v.IsZero()
}

func (m *Manager) get(name string) Value {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if e := m.entries[name]; e != nil {
		return e.value
	}
	return Value{}
}

// Status describes one secret for GET /system/secrets: whether it is set and where from, never its value or path.
type Status struct {
	Name   string `json:"name"`
	Set    bool   `json:"set"`
	Source Source `json:"source,omitempty"`
}

// Status lists every secret found in the environment: the fixed ones, then instance passwords and channel overrides
// by name. Instances that exist in the database but have no variable at all are added by the caller.
func (m *Manager) Status() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(m.entries))
	for name, e := range m.entries {
		out = append(out, Status{Name: name, Set: !e.value.IsZero(), Source: e.source})
	}
	order := map[string]int{VarSecretKey: 0, VarSessionKey: 1, VarLDAPBindPassword: 2}
	slices.SortFunc(out, func(a, b Status) int {
		ra, oka := order[a.Name]
		rb, okb := order[b.Name]
		switch {
		case oka && okb:
			return ra - rb
		case oka:
			return -1
		case okb:
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// Failure is a secret that failed to reload. Err never contains the value.
type Failure struct {
	Name string
	Err  error
}

// ReloadResult says what a reload changed. Callers rebuild what depends on a changed secret: the Pi-hole client for
// an instance password, the LDAP authenticator for the bind password. A changed session key invalidates every
// session and CSRF token; a changed master key makes tier 2 secrets sealed under the old key unreadable until
// rotate-key is run.
type ReloadResult struct {
	Changed []string
	Failed  []Failure
}

// Reload re-reads every secret that came from a *_FILE variable. A process can't see changes to its own environment,
// so plain variables keep their values until a restart. A secret that fails to load, or loads but is malformed,
// keeps its previous value and is reported in Failed.
func (m *Manager) Reload() ReloadResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res ReloadResult
	names := make([]string, 0, len(m.entries))
	for name := range m.entries {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		e := m.entries[name]
		if e.source != SourceFile {
			continue
		}
		v, err := readFile(e.path)
		if err != nil {
			res.Failed = append(res.Failed, Failure{Name: name, Err: fmt.Errorf("%s_FILE: %w", name, err)})
			continue
		}
		switch name {
		case VarSecretKey:
			c, err := cipherFrom(v)
			if err != nil {
				res.Failed = append(res.Failed, Failure{Name: name, Err: err})
				continue
			}
			if c.KeyID() == m.cipher.KeyID() {
				continue
			}
			m.cipher = c
		case VarSessionKey:
			k, err := DecodeKey(v.Reveal())
			if err != nil {
				res.Failed = append(res.Failed, Failure{Name: name, Err: err})
				continue
			}
			v = Value{b: k}
		}
		if v.Equal(e.value) {
			continue
		}
		e.value = v
		res.Changed = append(res.Changed, name)
	}
	return res
}
