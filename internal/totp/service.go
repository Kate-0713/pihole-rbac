// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

var (
	// ErrUnavailable means the app has no master key, so a secret can't be stored.
	ErrUnavailable = errors.New("totp: no master key to store the secret under")
	// ErrEnabled means the user already has TOTP on.
	ErrEnabled = errors.New("totp: already on")
	// ErrNotPending means there is no secret waiting for its first code.
	ErrNotPending = errors.New("totp: no secret is waiting to be confirmed")
	// ErrNotEnabled means the user doesn't have TOTP on.
	ErrNotEnabled = errors.New("totp: not on")
	// ErrInvalidCode covers a wrong code, one used before, one outside the accepted window, and text that is
	// neither a six-digit code nor a recovery code. Callers don't tell these apart to the user.
	ErrInvalidCode = errors.New("totp: invalid code")
)

// DefaultIssuer names the app in an authenticator's list.
const DefaultIssuer = "pihole-rbac"

// Actor is the logged-in user changing their own TOTP.
type Actor struct {
	UserID   int64
	Username string
	PublicID string // their session's public ID: the one session kept when the others end
	IP       string
}

// Service makes the changes to a user's own TOTP. Each runs in one transaction with its audit row.
type Service struct {
	Store *store.Store
	Audit *audit.Logger
	// Cipher returns the master key's cipher, or nil when there is no master key. It is asked each time, since a
	// reload can change the key.
	Cipher func() *secrets.Cipher
	// Issuer names the app in the authenticator's list. Empty means DefaultIssuer.
	Issuer string
	// Now returns the current time. nil means time.Now.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) cipher() *secrets.Cipher {
	if s.Cipher == nil {
		return nil
	}
	return s.Cipher()
}

// Status is a user's TOTP as their account page shows it.
type Status struct {
	Available         bool // a master key is set, so a secret can be stored
	Enabled           bool
	EnabledAt         time.Time // zero unless Enabled
	Pending           bool      // a secret is waiting for its first code
	Required          bool      // by their own setting or one of their roles'
	RecoveryCodesLeft int
}

// Status reads a user's TOTP. roleIDs are the roles their session holds.
func (s *Service) Status(ctx context.Context, userID int64, roleIDs []int64) (Status, error) {
	q := s.Store.Read()
	st := Status{Available: s.cipher() != nil}
	var err error
	if st.Required, err = RequiredFor(ctx, q, userID, roleIDs); err != nil {
		return Status{}, err
	}
	row, err := q.GetUserTOTP(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return Status{}, err
	}
	if !row.EnabledAt.Valid {
		st.Pending = true
		return st, nil
	}
	st.Enabled, st.EnabledAt = true, store.FromMillis(row.EnabledAt.Int64)
	left, err := q.CountUnusedRecoveryCodes(ctx, userID)
	st.RecoveryCodesLeft = int(left)
	return st, err
}

// Enrolment is a new secret in the three forms a user can take it.
type Enrolment struct {
	Secret string // base32, for typing in
	URI    string // otpauth://
	QR     string // the URI as a QR code, a data: URI for an <img>
}

// Setup makes a new secret for the user and stores it, not yet enabled. It replaces a secret that was never
// confirmed. It isn't audited: nothing about how the user logs in has changed yet.
func (s *Service) Setup(ctx context.Context, a Actor) (Enrolment, error) {
	c := s.cipher()
	if c == nil {
		return Enrolment{}, ErrUnavailable
	}
	secret := NewSecret()
	sealed, err := Seal(c, a.UserID, secret)
	if err != nil {
		return Enrolment{}, err
	}
	err = s.Store.WithTx(ctx, func(q *db.Queries) error {
		n, err := q.SetPendingUserTOTP(ctx, db.SetPendingUserTOTPParams{
			UserID: a.UserID, SecretCiphertext: sealed.Ciphertext, SecretNonce: sealed.Nonce, SecretKeyID: sealed.KeyID,
			CreatedAt: store.Millis(s.now()),
		})
		if err == nil && n == 0 {
			return ErrEnabled
		}
		return err
	})
	if err != nil {
		return Enrolment{}, err
	}
	issuer := s.Issuer
	if issuer == "" {
		issuer = DefaultIssuer
	}
	uri := URI(issuer, a.Username, secret)
	qr, err := QRDataURI(uri)
	if err != nil {
		return Enrolment{}, err
	}
	return Enrolment{Secret: Encode(secret), URI: uri, QR: qr}, nil
}

// Confirm turns TOTP on, given a six-digit code made from the secret Setup stored. It returns the recovery codes,
// which are shown once, and ends the user's other sessions. A recovery code can't confirm: there are none yet.
func (s *Service) Confirm(ctx context.Context, a Actor, code string) ([]string, error) {
	c := s.cipher()
	if c == nil {
		return nil, ErrUnavailable
	}
	now := s.now()
	entry := s.entry(a, audit.ActionTOTPEnable, now)
	var codes []string
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		row, err := q.GetUserTOTP(ctx, a.UserID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotPending
		}
		if err != nil {
			return err
		}
		if row.EnabledAt.Valid {
			return ErrEnabled
		}
		secret, err := Open(c, row)
		if err != nil {
			return err
		}
		step, ok := Verify(secret, code, now, 0)
		if !ok {
			return ErrInvalidCode
		}
		n, err := q.EnableUserTOTP(ctx, db.EnableUserTOTPParams{
			EnabledAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, LastStep: step, UserID: a.UserID,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEnabled
		}
		if codes, err = replaceRecoveryCodes(ctx, q, a.UserID); err != nil {
			return err
		}
		if err := endOtherSessions(ctx, q, a, &entry); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Audit.Log(entry)
	return codes, nil
}

// Disable turns the user's TOTP off, given a six-digit or recovery code, and ends their other sessions. The caller
// has checked their password.
func (s *Service) Disable(ctx context.Context, a Actor, code string) error {
	now := s.now()
	entry := s.entry(a, audit.ActionTOTPDisable, now)
	entry.Detail["by"] = "self"
	var used *audit.Entry
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if used, err = s.checkAudited(ctx, q, a, code, now); err != nil {
			return err
		}
		if _, err := q.DeleteUserTOTP(ctx, a.UserID); err != nil {
			return err
		}
		if err := endOtherSessions(ctx, q, a, &entry); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return err
	}
	s.log(used, entry)
	return nil
}

// RegenerateRecoveryCodes replaces the user's recovery codes, given a six-digit code or one of the current recovery
// codes, and returns the new ones.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, a Actor, code string) ([]string, error) {
	now := s.now()
	entry := s.entry(a, audit.ActionRecoveryCodesRegenerate, now)
	var used *audit.Entry
	var codes []string
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		var err error
		if used, err = s.checkAudited(ctx, q, a, code, now); err != nil {
			return err
		}
		if codes, err = replaceRecoveryCodes(ctx, q, a.UserID); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.log(used, entry)
	return codes, nil
}

// Check verifies a six-digit or recovery code for a user with TOTP on, inside the caller's transaction, and spends
// it: the code's time step is recorded, or the recovery code marked used, so it can't be used again. It returns
// ErrNotEnabled, or ErrInvalidCode with nothing changed. recovery says a recovery code was used, which the caller
// audits as recovery_code_used.
func Check(ctx context.Context, q *db.Queries, c *secrets.Cipher, userID int64, input string, now time.Time) (recovery bool, err error) {
	row, err := q.GetUserTOTP(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotEnabled
	}
	if err != nil {
		return false, err
	}
	if !row.EnabledAt.Valid {
		return false, ErrNotEnabled
	}
	if hash, ok := HashRecoveryCode(input); ok {
		n, err := q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{
			UsedAt: sql.NullInt64{Int64: store.Millis(now), Valid: true}, UserID: userID, CodeHash: hash,
		})
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, ErrInvalidCode
		}
		return true, nil
	}
	if c == nil {
		return false, ErrUnavailable
	}
	secret, err := Open(c, row)
	if err != nil {
		return false, err
	}
	step, ok := Verify(secret, input, now, row.LastStep)
	if !ok {
		return false, ErrInvalidCode
	}
	n, err := q.AdvanceUserTOTPStep(ctx, db.AdvanceUserTOTPStepParams{Step: step, UserID: userID})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, ErrInvalidCode // another request used this code first
	}
	return false, nil
}

// CheckLogin verifies and spends a code for the second step of a login, inside the caller's transaction. When a
// recovery code was used it writes the recovery_code_used row and returns it, for the caller to pass to the audit
// logger once the transaction has committed. Errors are Check's.
func (s *Service) CheckLogin(ctx context.Context, q *db.Queries, a Actor, code string) (*audit.Entry, error) {
	return s.checkAudited(ctx, q, a, code, s.now())
}

// checkAudited is Check, with the recovery_code_used row written when a recovery code was used. The row is returned
// for its log line once the transaction has committed.
func (s *Service) checkAudited(ctx context.Context, q *db.Queries, a Actor, code string, now time.Time) (*audit.Entry, error) {
	recovery, err := Check(ctx, q, s.cipher(), a.UserID, code, now)
	if err != nil || !recovery {
		return nil, err
	}
	left, err := q.CountUnusedRecoveryCodes(ctx, a.UserID)
	if err != nil {
		return nil, err
	}
	used := s.entry(a, audit.ActionRecoveryCodeUsed, now)
	used.Detail["left"] = left
	if _, err := audit.Insert(ctx, q, used); err != nil {
		return nil, err
	}
	return &used, nil
}

func (s *Service) entry(a Actor, action string, now time.Time) audit.Entry {
	return audit.Entry{
		At: now, UserID: a.UserID, Username: a.Username, Action: action, Target: "user:" + a.Username, IP: a.IP,
		Detail: map[string]any{"user_id": a.UserID},
	}
}

func (s *Service) log(used *audit.Entry, entry audit.Entry) {
	if used != nil {
		s.Audit.Log(*used)
	}
	s.Audit.Log(entry)
}

// replaceRecoveryCodes gives the user a fresh set of recovery codes and returns them. Any they had stop working.
func replaceRecoveryCodes(ctx context.Context, q *db.Queries, userID int64) ([]string, error) {
	if err := q.DeleteRecoveryCodes(ctx, userID); err != nil {
		return nil, err
	}
	codes, hashes := NewRecoveryCodes()
	for _, h := range hashes {
		if err := q.AddRecoveryCode(ctx, db.AddRecoveryCodeParams{UserID: userID, CodeHash: h}); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// endOtherSessions ends every session of the actor's but the one they are using, as a password change does: whoever
// else is logged in as them shouldn't outlast a change to how they log in.
func endOtherSessions(ctx context.Context, q *db.Queries, a Actor, entry *audit.Entry) error {
	n, err := q.DeleteUserSessionsExcept(ctx, db.DeleteUserSessionsExceptParams{UserID: a.UserID, PublicID: a.PublicID})
	if err == nil && n > 0 {
		entry.Detail["sessions_ended"] = n
	}
	return err
}
