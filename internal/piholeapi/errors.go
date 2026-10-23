// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"errors"
	"fmt"
)

// Callers tell failures apart with errors.Is and errors.As rather than by parsing messages: Pi-hole being down is a
// different problem from Pi-hole refusing one request. Kind turns an error into the API's error code.

// ErrUnreachable matches any failure to get a response at all: connection refused, DNS failure, TLS failure, timeout.
var ErrUnreachable = errors.New("pihole unreachable")

// ErrAuthRejected means Pi-hole answered but refused the instance's app password.
var ErrAuthRejected = errors.New("pihole rejected the app password")

// ErrBadResponse means Pi-hole answered with something that isn't the JSON this client expects.
var ErrBadResponse = errors.New("pihole sent an unexpected response")

// ErrInvalidArgument means a value that goes into a Pi-hole API path isn't on the allowed list. Handlers validate
// first; this is the backstop.
var ErrInvalidArgument = errors.New("piholeapi: invalid argument")

// ErrClosed means the client was closed, usually because the instance was edited or disabled while a request was
// in flight.
var ErrClosed = errors.New("piholeapi: client closed")

// StatusError is a call that got an HTTP status outside 2xx.
type StatusError struct {
	Code         int
	Method, Path string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("pihole returned status %d for %s %s", e.Code, e.Method, e.Path)
}

// unreachableError keeps the underlying error for the logs while matching ErrUnreachable.
type unreachableError struct {
	op  string
	err error
}

func (e *unreachableError) Error() string        { return e.op + " pihole: " + e.err.Error() }
func (e *unreachableError) Unwrap() error        { return e.err }
func (e *unreachableError) Is(target error) bool { return target == ErrUnreachable }

type badResponseError struct {
	what string
	err  error
}

func (e *badResponseError) Error() string {
	return "pihole sent an unexpected " + e.what + ": " + e.err.Error()
}
func (e *badResponseError) Unwrap() error        { return e.err }
func (e *badResponseError) Is(target error) bool { return target == ErrBadResponse }

// API error codes for Pi-hole failures.
const (
	CodeUnreachable  = "pihole_unreachable"
	CodeAuthRejected = "pihole_auth_rejected"
	CodeStatusError  = "pihole_status_error"
)

// Kind returns the API error code for err, or "" if err isn't a Pi-hole failure (a cancelled request, say, or a bug).
// An unexpected response body counts as a status error: Pi-hole answered, but not usefully.
func Kind(err error) string {
	var se *StatusError
	switch {
	case errors.Is(err, ErrUnreachable):
		return CodeUnreachable
	case errors.Is(err, ErrAuthRejected):
		return CodeAuthRejected
	case errors.As(err, &se), errors.Is(err, ErrBadResponse):
		return CodeStatusError
	}
	return ""
}

// Down reports whether err means the instance can't be used at all right now (not there, or refusing the password),
// as opposed to one request being refused. Further calls to the same instance would only fail the same way, slowly.
func Down(err error) bool {
	return errors.Is(err, ErrUnreachable) || errors.Is(err, ErrAuthRejected)
}
