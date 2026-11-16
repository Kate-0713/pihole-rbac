// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"net/http"
)

const (
	// CSRFHeader carries the token on every state-changing request. The API takes JSON only, so there is no form
	// field fallback.
	CSRFHeader = "X-CSRF-Token"

	// AnonCookie identifies a visitor who isn't logged in yet, so the login request can carry a token too. It holds
	// no secret: the token is an HMAC of it under the session key.
	AnonCookie = "pihole_rbac_anon"

	anonIDSize = 16
)

// CSRFToken returns the token for the request's session.
func (s *Sessions) CSRFToken(sess *Session) string {
	return s.sign("csrf|session", sess.id)
}

// AnonCSRFToken returns the token for a visitor without a session, bound to their anonymous cookie. A visitor
// without one is given it on w, so call this before anything is written to the response.
func (s *Sessions) AnonCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	id, err := s.EnsureAnonID(w, r)
	if err != nil {
		return "", err
	}
	return s.sign("csrf|anon", id), nil
}

// EnsureAnonID returns the request's anonymous cookie ID. A visitor without one is given it on w, so call this
// before anything is written to the response. Besides binding the anonymous CSRF token, the ID ties the second step
// of a two-factor login to the browser that sent the password.
func (s *Sessions) EnsureAnonID(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if id, ok := anonID(r); ok {
		return id, nil
	}
	id := make([]byte, anonIDSize)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     AnonCookie,
		Value:    b64.EncodeToString(id),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Secure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return id, nil
}

// AnonID returns the request's anonymous cookie ID, if it carries a well-formed one.
func AnonID(r *http.Request) ([]byte, bool) {
	return anonID(r)
}

func anonID(r *http.Request) ([]byte, bool) {
	c, err := r.Cookie(AnonCookie)
	if err != nil {
		return nil, false
	}
	id, err := b64.DecodeString(c.Value)
	if err != nil || len(id) != anonIDSize {
		return nil, false
	}
	return id, true
}

// CheckCSRF reports whether r carries the right X-CSRF-Token: the session's token if sess is non-nil, otherwise the
// token for the request's anonymous cookie. A token bound to one session is useless in another, and an anonymous
// token is useless once there is a session.
func (s *Sessions) CheckCSRF(r *http.Request, sess *Session) bool {
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		return false
	}
	var want string
	if sess != nil {
		want = s.CSRFToken(sess)
	} else {
		id, ok := anonID(r)
		if !ok {
			return false
		}
		want = s.sign("csrf|anon", id)
	}
	return hmac.Equal([]byte(got), []byte(want))
}

// CheckRequestCSRF looks up the request's session itself, for callers that haven't already.
func (s *Sessions) CheckRequestCSRF(ctx context.Context, r *http.Request) (bool, error) {
	sess, err := s.Get(ctx, r)
	if errors.Is(err, ErrNoSession) {
		return s.CheckCSRF(r, nil), nil
	}
	if err != nil {
		return false, err
	}
	return s.CheckCSRF(r, sess), nil
}
