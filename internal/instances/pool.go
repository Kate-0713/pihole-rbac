// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package instances keeps one Pi-hole client per enabled instance and tracks each instance's health. An instance
// found down (unreachable, or refusing its password) is skipped for a short backoff, so one offline Pi-hole doesn't
// make every request that touches it wait out a timeout, and never slows requests for the others.
package instances

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// Instance is the configuration of one Pi-hole, as stored in the instances table.
type Instance struct {
	ID        int64
	Name      string
	BaseURL   string
	EnvName   string
	TLSMode   piholeapi.TLSMode
	CAFile    string
	Enabled   bool
	CreatedAt time.Time
}

// Passwords supplies instance passwords. *secrets.Manager implements it.
type Passwords interface {
	InstancePassword(envName string) (secrets.Value, bool)
}

var (
	// ErrNotFound means there is no enabled instance with that ID in the pool.
	ErrNotFound = errors.New("instances: no enabled instance with that ID")
	// ErrNoPassword means the instance's password variable isn't set. The error names the variable.
	ErrNoPassword = errors.New("instance password is not set")
	// ErrMisconfigured means a client couldn't be built from the instance's settings (an unreadable CA file, say).
	ErrMisconfigured = errors.New("instance is misconfigured")
)

// Error codes for an instance that can't be used, in addition to piholeapi's.
const (
	CodePasswordMissing = "instance_password_missing"
	CodeMisconfigured   = "instance_misconfigured"
)

// Kind returns the API error code for an error from the pool or a Pi-hole call, or "" if it is neither.
func Kind(err error) string {
	switch {
	case errors.Is(err, ErrNoPassword):
		return CodePasswordMissing
	case errors.Is(err, ErrMisconfigured):
		return CodeMisconfigured
	}
	return piholeapi.Kind(err)
}

// State is an instance's health at its last call.
type State string

const (
	StateUnknown State = "unknown" // not called yet
	StateUp      State = "up"      // Pi-hole answered with the password accepted
	StateDown    State = "down"    // unreachable, password refused, missing or misconfigured
)

// Health is what the pool knows about an instance. It lives in memory and starts again as unknown on a restart or
// when the instance's settings change. LastError is an error code, never a message: the message can name internal
// addresses, so it goes to the log only.
type Health struct {
	State       State
	LastSuccess time.Time // zero if never
	LastFailure time.Time // zero if never
	LastError   string    // code of the last failure, kept after a later success
}

// Defaults for Options.
const (
	DefaultBackoff       = 15 * time.Second
	DefaultProbeInterval = time.Minute
)

// Options configures a Pool.
type Options struct {
	Passwords Passwords
	// Timeout bounds each Pi-hole request (default piholeapi.DefaultTimeout).
	Timeout time.Duration
	// Backoff is how long calls to a down instance fail at once with its last error (default 15s). The probe ignores
	// it, so recovery is noticed within ProbeInterval at the latest.
	Backoff time.Duration
	// ProbeInterval is how often Run checks instances that haven't been called for that long (default 1m).
	ProbeInterval time.Duration
	Logger        *slog.Logger
}

// Pool holds the clients of the enabled instances. It is safe for concurrent use.
type Pool struct {
	passwords  Passwords
	timeout    time.Duration
	backoff    time.Duration
	probeEvery time.Duration
	logger     *slog.Logger
	now        func() time.Time

	mu      sync.RWMutex
	members map[int64]*member
	closed  bool

	retiring sync.WaitGroup // replaced clients being logged out
}

type member struct {
	inst     Instance
	password secrets.Value
	client   *piholeapi.Client // nil if setupErr is set
	setupErr error

	mu        sync.Mutex
	name      string // can change without replacing the member
	health    Health
	lastErr   error
	downUntil time.Time
	lastUsed  time.Time
}

// New makes an empty pool.
func New(opts Options) *Pool {
	p := &Pool{
		passwords:  opts.Passwords,
		timeout:    opts.Timeout,
		backoff:    opts.Backoff,
		probeEvery: opts.ProbeInterval,
		logger:     opts.Logger,
		now:        time.Now,
		members:    map[int64]*member{},
	}
	if p.timeout <= 0 {
		p.timeout = piholeapi.DefaultTimeout
	}
	if p.backoff <= 0 {
		p.backoff = DefaultBackoff
	}
	if p.probeEvery <= 0 {
		p.probeEvery = DefaultProbeInterval
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}
	return p
}

// Load makes the pool match insts: enabled instances are added or updated, and everything else is removed.
func (p *Pool) Load(insts []Instance) {
	keep := make(map[int64]bool, len(insts))
	for _, inst := range insts {
		if inst.Enabled {
			keep[inst.ID] = true
		}
		p.Put(inst)
	}
	p.mu.RLock()
	var gone []int64
	for id := range p.members {
		if !keep[id] {
			gone = append(gone, id)
		}
	}
	p.mu.RUnlock()
	for _, id := range gone {
		p.Remove(id)
	}
}

// Put adds or updates one instance, after its row has been committed. A disabled instance is removed. If nothing
// that affects the connection changed (the base URL, TLS settings, env name or password), the existing client and
// its Pi-hole session are kept; otherwise the client is replaced, the old one logged out, and the health reset.
// It reports whether a new client was built.
func (p *Pool) Put(inst Instance) bool {
	if !inst.Enabled {
		p.Remove(inst.ID)
		return false
	}
	pw, _ := p.passwords.InstancePassword(inst.EnvName)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	old := p.members[inst.ID]
	// A member that couldn't be built is rebuilt (the CA file may have been fixed), unless it is only waiting for its
	// password, which nothing here can change.
	if old != nil && old.sameConnection(inst, pw) && (old.client != nil || pw.IsZero()) {
		old.mu.Lock()
		old.name = inst.Name
		old.mu.Unlock()
		return false
	}
	p.members[inst.ID] = p.newMember(inst, pw)
	p.retire(old)
	return true
}

// Remove drops an instance and logs its client out.
func (p *Pool) Remove(id int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.members[id]
	delete(p.members, id)
	p.retire(old)
}

func (m *member) sameConnection(inst Instance, pw secrets.Value) bool {
	return m.inst.sameConnection(inst) && m.password.Equal(pw)
}

func (p *Pool) newMember(inst Instance, pw secrets.Value) *member {
	m := &member{inst: inst, password: pw, name: inst.Name, health: Health{State: StateUnknown}}
	if pw.IsZero() {
		m.setupErr = fmt.Errorf("%w: set %s", ErrNoPassword, secrets.InstanceVar(inst.EnvName))
	} else {
		c, err := piholeapi.New(piholeapi.Options{
			BaseURL: inst.BaseURL, Password: pw, TLSMode: inst.TLSMode, CAFile: inst.CAFile, Timeout: p.timeout,
		})
		if err != nil {
			m.setupErr = fmt.Errorf("%w: %v", ErrMisconfigured, err)
		}
		m.client = c
	}
	if m.setupErr != nil {
		m.health = Health{State: StateDown, LastFailure: p.now(), LastError: Kind(m.setupErr)}
		p.logger.Warn("pi-hole instance can't be used", "instance", inst.Name, "error", m.setupErr)
	}
	return m
}

// retire logs out a replaced client in the background. Called with p.mu held.
func (p *Pool) retire(m *member) {
	if m == nil || m.client == nil {
		return
	}
	p.retiring.Add(1)
	go func() {
		defer p.retiring.Done()
		ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
		defer cancel()
		if err := m.client.Close(ctx); err != nil {
			p.logger.Debug("pi-hole logout failed", "instance", m.inst.Name, "error", err)
		}
	}()
}

func (p *Pool) get(id int64) *member {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.members[id]
}

// Do runs fn with the instance's client and records the outcome in its health. While the instance is in its backoff
// after being found down, Do returns its last error without calling fn.
func (p *Pool) Do(ctx context.Context, id int64, fn func(context.Context, *piholeapi.Client) error) error {
	for attempt := 0; ; attempt++ {
		m := p.get(id)
		if m == nil {
			return ErrNotFound
		}
		if m.setupErr != nil {
			return m.setupErr
		}
		if err := m.backingOff(p.now()); err != nil {
			return err
		}
		err := fn(ctx, m.client)
		// The instance was edited or disabled while fn ran, which closed the client. Try once with what replaced it.
		if errors.Is(err, piholeapi.ErrClosed) && attempt == 0 {
			continue
		}
		p.record(ctx, m, err)
		return err
	}
}

func (m *member) backingOff(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastErr != nil && now.Before(m.downUntil) {
		return m.lastErr
	}
	return nil
}

// record updates an instance's health after a call. A call the caller cancelled, or one that failed before reaching
// Pi-hole for a reason that says nothing about it, leaves the health alone.
func (p *Pool) record(ctx context.Context, m *member, err error) {
	if err != nil && (ctx.Err() != nil || piholeapi.Kind(err) == "") {
		return
	}
	now := p.now()
	m.mu.Lock()
	prev := m.health.State
	m.lastUsed = now
	switch {
	// Pi-hole refusing the content of a request (a duplicate domain, say) is the caller's problem, not Pi-hole's.
	case err == nil, errors.Is(err, piholeapi.ErrRejected):
		m.health.State, m.health.LastSuccess = StateUp, now
		m.lastErr, m.downUntil = nil, time.Time{}
	case piholeapi.Down(err):
		m.health.State, m.health.LastFailure, m.health.LastError = StateDown, now, piholeapi.Kind(err)
		m.lastErr, m.downUntil = err, now.Add(p.backoff)
	default: // Pi-hole answered but refused or garbled this one request: it is up.
		m.health.State, m.health.LastFailure, m.health.LastError = StateUp, now, piholeapi.Kind(err)
		m.lastErr, m.downUntil = nil, time.Time{}
	}
	state, name := m.health.State, m.name
	m.mu.Unlock()

	switch {
	case state == StateDown && prev != StateDown:
		p.logger.Warn("pi-hole instance is down", "instance", name, "error", err)
	case state == StateUp && prev == StateDown:
		p.logger.Info("pi-hole instance is back up", "instance", name)
	}
}

// Name returns an enabled instance's current name, and false if it isn't in the pool.
func (p *Pool) Name(id int64) (string, bool) {
	m := p.get(id)
	if m == nil {
		return "", false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.name, true
}

// Health returns an instance's health, and false if it isn't in the pool (unknown or disabled).
func (p *Pool) Health(id int64) (Health, bool) {
	m := p.get(id)
	if m == nil {
		return Health{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.health, true
}

// Probe checks every instance that hasn't been called within the probe interval, in parallel, ignoring the backoff.
func (p *Pool) Probe(ctx context.Context) {
	cutoff := p.now().Add(-p.probeEvery)
	p.mu.RLock()
	var due []*member
	for _, m := range p.members {
		if m.client == nil {
			continue
		}
		m.mu.Lock()
		idle := m.lastUsed.Before(cutoff)
		m.mu.Unlock()
		if idle {
			due = append(due, m)
		}
	}
	p.mu.RUnlock()

	var wg sync.WaitGroup
	for _, m := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.client.GetStatus(ctx)
			p.record(ctx, m, err)
		}()
	}
	wg.Wait()
}

// Run probes at once and then every probe interval until ctx is done.
func (p *Pool) Run(ctx context.Context) {
	p.Probe(ctx)
	t := time.NewTicker(p.probeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Probe(ctx)
		}
	}
}

// ReloadPasswords rebuilds the client of every instance whose password changed, after a secrets reload. The others
// keep their sessions. It returns the names of the instances that got a new client.
func (p *Pool) ReloadPasswords() []string {
	p.mu.RLock()
	insts := make([]Instance, 0, len(p.members))
	for _, m := range p.members {
		inst := m.inst
		m.mu.Lock()
		inst.Name = m.name
		m.mu.Unlock()
		insts = append(insts, inst)
	}
	p.mu.RUnlock()
	var rebuilt []string
	for _, inst := range insts {
		if p.Put(inst) {
			rebuilt = append(rebuilt, inst.Name)
		}
	}
	return rebuilt
}

// Test connects to an instance with the given settings and the current password, using a throwaway client: it logs
// in, reads the blocking status and logs out. The pool and its health aren't touched, so settings can be tested
// before they are saved or enabled.
func (p *Pool) Test(ctx context.Context, inst Instance) error {
	pw, ok := p.passwords.InstancePassword(inst.EnvName)
	if !ok {
		return fmt.Errorf("%w: set %s", ErrNoPassword, secrets.InstanceVar(inst.EnvName))
	}
	c, err := piholeapi.New(piholeapi.Options{
		BaseURL: inst.BaseURL, Password: pw, TLSMode: inst.TLSMode, CAFile: inst.CAFile, Timeout: p.timeout,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMisconfigured, err)
	}
	_, err = c.GetStatus(ctx)
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timeout)
	defer cancel()
	_ = c.Close(closeCtx)
	return err
}

// Close logs out every client and waits for the logouts, or for ctx. The pool can't be used afterwards.
func (p *Pool) Close(ctx context.Context) {
	p.mu.Lock()
	p.closed = true
	for id, m := range p.members {
		delete(p.members, id)
		p.retire(m)
	}
	p.mu.Unlock()
	done := make(chan struct{})
	go func() {
		p.retiring.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
