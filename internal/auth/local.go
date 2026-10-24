// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost is the cost used for new password hashes. Hashes made at another cost (imported from v1, say) still
// verify.
const BcryptCost = bcrypt.DefaultCost

const (
	minPasswordLen   = 12 // characters
	maxPasswordBytes = 72 // bcrypt rejects anything longer
)

// These messages are shown to admins as they are, so they're written to be read.
var (
	ErrInvalidUsername  = errors.New("username must be 1-64 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", minPasswordLen)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d bytes", maxPasswordBytes)
)

// ErrUserNotFound is returned by a LocalUserStore for a username with no local account.
var ErrUserNotFound = errors.New("no such local user")

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateUsername enforces the rules for new usernames: lowercase only, and a limited character set so the name is
// safe in URLs and log lines.
func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return ErrInvalidUsername
	}
	return nil
}

// ValidatePassword enforces the minimum length and bcrypt's 72-byte limit.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return ErrPasswordTooShort
	}
	if len(password) > maxPasswordBytes {
		return ErrPasswordTooLong
	}
	return nil
}

// HashPassword validates password and returns its bcrypt hash.
func HashPassword(password string) ([]byte, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	return bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
}

// CheckPassword reports whether password matches a bcrypt hash.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// LocalUser is what the local authenticator needs from a users row.
type LocalUser struct {
	ID           int64
	Username     string
	PasswordHash []byte
	Disabled     bool
}

// LocalUserStore looks up local accounts. It returns ErrUserNotFound for a username with no local account (including
// one that belongs to an LDAP user).
type LocalUserStore interface {
	LocalUserByName(ctx context.Context, username string) (LocalUser, error)
}

// LocalAuthenticator checks usernames and passwords against local accounts. It is break-glass access when LDAP is
// unreachable.
type LocalAuthenticator struct {
	users LocalUserStore
}

func NewLocalAuthenticator(users LocalUserStore) *LocalAuthenticator {
	return &LocalAuthenticator{users: users}
}

var (
	dummyHashOnce  sync.Once
	dummyHashValue []byte
)

// dummyHash is a throwaway bcrypt hash, at the same cost as real ones, compared against when the username doesn't
// exist. Generated once, lazily.
func dummyHash() []byte {
	dummyHashOnce.Do(func() {
		dummyHashValue, _ = bcrypt.GenerateFromPassword([]byte("pihole-rbac-dummy"), BcryptCost)
	})
	return dummyHashValue
}

func (a *LocalAuthenticator) Authenticate(ctx context.Context, username, password string) (*Identity, error) {
	username = NormalizeUsername(username)
	u, err := a.users.LocalUserByName(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		// Spend the same bcrypt time as a real check, so response time doesn't reveal which usernames exist.
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}
	// Checked after the password, so a disabled account takes as long to refuse as a wrong password.
	if u.Disabled {
		return nil, ErrInvalidCredentials
	}
	return &Identity{Username: u.Username, Source: MethodLocal, UserID: u.ID}, nil
}
