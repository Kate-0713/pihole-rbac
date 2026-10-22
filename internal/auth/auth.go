// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth verifies who a user is: local accounts with bcrypt passwords, LDAP, and the chain that tries the
// enabled methods in order. It says nothing about what the user may do; roles and permissions are resolved from the
// returned Identity by the rbac package.
package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// ErrInvalidCredentials covers a wrong password, an unknown username and a disabled account alike, so a login
// response never reveals which usernames exist.
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrNoAccess means the credentials were correct, but the user holds no role in this app. It is kept distinct from
// ErrInvalidCredentials so the login page can say so instead of implying a typo, and so the audit log can record it
// as its own event.
var ErrNoAccess = errors.New("authenticated but not authorised for this app")

// Method is a login method.
type Method string

const (
	MethodLocal Method = "local"
	MethodLDAP  Method = "ldap"
)

// AllMethods lists the known methods in their default order: local first, so an unreachable LDAP server can't get
// in the way of a break-glass login.
func AllMethods() []Method { return []Method{MethodLocal, MethodLDAP} }

// ValidateMethods checks an ordered list of enabled methods: at least one, all known, none repeated.
func ValidateMethods(methods []Method) error {
	if len(methods) == 0 {
		return errors.New("at least one login method must be enabled")
	}
	seen := map[Method]bool{}
	for _, m := range methods {
		if !slices.Contains(AllMethods(), m) {
			return fmt.Errorf("unknown login method %q", m)
		}
		if seen[m] {
			return fmt.Errorf("login method %q is listed twice", m)
		}
		seen[m] = true
	}
	return nil
}

// Identity is who a successful login proved the user to be.
type Identity struct {
	Username string
	Source   Method
	UserID   int64    // users.id for a local user; 0 for an LDAP user, whose row is created or found at login
	DN       string   // LDAP only
	Groups   []string // LDAP only: the DNs of the groups the user is a member of
}

// Authenticator verifies credentials. It returns ErrInvalidCredentials for bad credentials and any other error for
// an operational failure (LDAP unreachable, database error).
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (*Identity, error)
}

// NormalizeUsername is applied to every username before it is looked up, rate-limited or stored. Usernames are
// lowercase, so "Alice " and "alice" are the same account.
func NormalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// namedAuthenticator pairs an Authenticator with the method it implements, so failures can be reported against the
// right one.
type namedAuthenticator struct {
	method Method
	auth   Authenticator
}

// ChainAuthenticator tries each enabled method in order and accepts the login as soon as one does.
type ChainAuthenticator struct {
	methods []namedAuthenticator
}

// Authenticate returns the first successful result. If none succeed:
//   - if any method verified the credentials but found no role for the user (ErrNoAccess), that's returned so the
//     login page can say so;
//   - otherwise ErrInvalidCredentials, wrapping any operational errors (LDAP unreachable, bad service account, ...)
//     so the audit log keeps the real reason while the browser only ever sees the generic message.
func (c *ChainAuthenticator) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	var noAccess error
	var opErrs []error

	for _, m := range c.methods {
		id, err := m.auth.Authenticate(ctx, username, password)
		switch {
		case err == nil:
			return id, nil
		case errors.Is(err, ErrNoAccess):
			noAccess = err
		case errors.Is(err, ErrInvalidCredentials):
			// expected for a wrong password or a user this method doesn't know
		default:
			opErrs = append(opErrs, fmt.Errorf("%s: %w", m.method, err))
		}
	}

	if noAccess != nil {
		return nil, noAccess
	}
	if len(opErrs) > 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCredentials, errors.Join(opErrs...))
	}
	return nil, ErrInvalidCredentials
}

// Build returns a chain of the enabled methods, in the order given. available maps each method to its
// Authenticator; every enabled method must have one.
func Build(enabled []Method, available map[Method]Authenticator) (*ChainAuthenticator, error) {
	if err := ValidateMethods(enabled); err != nil {
		return nil, err
	}
	chain := &ChainAuthenticator{}
	for _, m := range enabled {
		a := available[m]
		if a == nil {
			return nil, fmt.Errorf("login method %q is enabled but not configured", m)
		}
		chain.methods = append(chain.methods, namedAuthenticator{m, a})
	}
	return chain, nil
}

// SwappableAuthenticator lets the authenticator be replaced while requests are being served, for when the login
// methods or LDAP settings are saved, or the LDAP bind password is reloaded. A request already in flight completes
// against whichever Authenticator was current when it started.
type SwappableAuthenticator struct {
	mu    sync.RWMutex
	inner Authenticator
}

func NewSwappable(initial Authenticator) *SwappableAuthenticator {
	return &SwappableAuthenticator{inner: initial}
}

func (s *SwappableAuthenticator) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	s.mu.RLock()
	inner := s.inner
	s.mu.RUnlock()
	return inner.Authenticate(ctx, username, password)
}

// Set replaces the underlying Authenticator.
func (s *SwappableAuthenticator) Set(a Authenticator) {
	s.mu.Lock()
	s.inner = a
	s.mu.Unlock()
}
