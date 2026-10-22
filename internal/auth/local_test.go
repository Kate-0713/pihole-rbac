// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// fakeUsers is an in-memory LocalUserStore. lookups records every username asked for.
type fakeUsers struct {
	users   map[string]LocalUser
	err     error
	lookups []string
}

func (f *fakeUsers) LocalUserByName(_ context.Context, username string) (LocalUser, error) {
	f.lookups = append(f.lookups, username)
	if f.err != nil {
		return LocalUser{}, f.err
	}
	u, ok := f.users[username]
	if !ok {
		return LocalUser{}, ErrUserNotFound
	}
	return u, nil
}

func mustHash(t *testing.T, pw string) []byte {
	t.Helper()
	// Tests use the minimum cost; BcryptCost is checked separately.
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestLocalAuthenticate(t *testing.T) {
	store := &fakeUsers{users: map[string]LocalUser{
		"alice": {ID: 7, Username: "alice", PasswordHash: mustHash(t, "correct horse battery")},
		"dave":  {ID: 8, Username: "dave", PasswordHash: mustHash(t, "correct horse battery"), Disabled: true},
	}}
	a := NewLocalAuthenticator(store)
	ctx := context.Background()

	tests := []struct {
		name, user, pw string
		wantErr        error
	}{
		{"correct", "alice", "correct horse battery", nil},
		{"username is normalised", "  Alice ", "correct horse battery", nil},
		{"wrong password", "alice", "wrong", ErrInvalidCredentials},
		{"password is case-sensitive", "alice", "Correct horse battery", ErrInvalidCredentials},
		{"unknown user", "nobody", "correct horse battery", ErrInvalidCredentials},
		{"disabled user, right password", "dave", "correct horse battery", ErrInvalidCredentials},
		{"empty password", "alice", "", ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := a.Authenticate(ctx, tt.user, tt.pw)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || id != nil {
					t.Fatalf("got %+v, %v; want %v", id, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if id.Username != "alice" || id.Source != MethodLocal || id.UserID != 7 {
				t.Fatalf("identity = %+v", id)
			}
		})
	}
	if store.lookups[1] != "alice" {
		t.Fatalf("looked up %q, want the normalised username", store.lookups[1])
	}
}

func TestLocalAuthenticateStoreErrorIsOperational(t *testing.T) {
	a := NewLocalAuthenticator(&fakeUsers{err: errors.New("database is locked")})
	_, err := a.Authenticate(context.Background(), "alice", "pw")
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v; want an operational error, not invalid credentials", err)
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name, in string
		ok       bool
	}{
		{"simple", "alice", true},
		{"digits and punctuation", "a.b_c-9", true},
		{"64 characters", strings.Repeat("a", 64), true},
		{"65 characters", strings.Repeat("a", 65), false},
		{"uppercase", "Alice", false},
		{"empty", "", false},
		{"path characters", "a/b", false},
		{"leading dot", ".alice", false},
		{"space", "al ice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateUsername(tt.in); (err == nil) != tt.ok {
				t.Fatalf("ValidateUsername(%q) = %v", tt.in, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name, in string
		want     error
	}{
		{"eleven characters", "eleven char", ErrPasswordTooShort},
		{"exactly twelve characters", "twelve chars", nil},
		{"twelve characters, more bytes", "ééééééééééé1", nil},
		{"exactly 72 bytes", strings.Repeat("x", 72), nil},
		{"73 bytes", strings.Repeat("x", 73), ErrPasswordTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePassword(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("alice-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h), "alice-password-1") {
		t.Fatal("hash contains the password")
	}
	if cost, _ := bcrypt.Cost(h); cost != BcryptCost {
		t.Fatalf("cost = %d, want %d", cost, BcryptCost)
	}
	if bcrypt.CompareHashAndPassword(h, []byte("alice-password-1")) != nil {
		t.Fatal("hash doesn't verify")
	}
	if _, err := HashPassword("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("short password: err = %v", err)
	}
}

func TestNormalizeUsername(t *testing.T) {
	if got := NormalizeUsername("  Alice\t"); got != "alice" {
		t.Fatalf("got %q", got)
	}
}
