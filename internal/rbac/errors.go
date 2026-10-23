// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package rbac

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Code is the kind of refusal. The values are the API's error codes, so the API layer can pass them straight through.
type Code string

const (
	CodeValidation   Code = "validation_failed"
	CodeNotFound     Code = "not_found"
	CodeForbidden    Code = "forbidden"
	CodeConflict     Code = "conflict"
	CodeInvariant    Code = "invariant_violated"
	CodeConfirmation Code = "confirmation_required"
)

// Error is a refusal with a message that is safe to show to the user, and optional structured details.
type Error struct {
	Code    Code
	Message string
	Details map[string]any
}

func (e *Error) Error() string { return e.Message }

func newError(code Code, details map[string]any, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Details: details}
}

// Forbidden is the refusal for a missing global permission.
func Forbidden(p Permission) *Error {
	return newError(CodeForbidden, map[string]any{"permission": string(p)}, "You need the %s permission to do that.", p)
}

// ForbiddenOn is the refusal for a permission missing on one instance or group.
func ForbiddenOn(p Permission, t Target) *Error {
	return newError(CodeForbidden, map[string]any{"permission": string(p), "target": t.String()},
		"You need the %s permission on %s to do that.", p, t)
}

// ForbiddenAny is the refusal for a target the user holds no permission on at all.
func ForbiddenAny(t Target) *Error {
	return newError(CodeForbidden, map[string]any{"target": t.String()}, "You don't have access to %s.", t)
}

// AsError returns err as an *Error, if it is one.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// IsCode reports whether err is an *Error with the given code.
func IsCode(err error, code Code) bool {
	e, ok := AsError(err)
	return ok && e.Code == code
}

func grantStrings(gs []Grant) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.String()
	}
	return out
}

func joinGrants(gs []Grant) string { return joinStrings(grantStrings(gs)) }

func joinPermissions(ps []Permission) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = string(p)
	}
	return joinStrings(s)
}

// joinStrings joins with commas and a final "and": "a", "a and b", "a, b and c".
func joinStrings(s []string) string {
	switch len(s) {
	case 0:
		return ""
	case 1:
		return s[0]
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}

func containsID(ids []int64, id int64) bool { return slices.Contains(ids, id) }

func withoutID(ids []int64, id int64) []int64 {
	return slices.DeleteFunc(slices.Clone(ids), func(x int64) bool { return x == id })
}
