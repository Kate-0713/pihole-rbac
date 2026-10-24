// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// Every Pi-hole write answers with one result per instance it acted on (see WriteResults in the spec): ok, failed,
// or skipped when the instance wasn't asked. The response is 200 when every result is ok and 207 when they differ.
// When none is ok, the request fails with the first failure's error envelope, carrying all the results in
// details.results, so a plain failure still reads as one. A target is a single instance for now, so it has one
// result; a mirrored group will have one per member.

// outcome is how one instance's part of a write went.
type outcome struct {
	ref     instanceRef
	ran     bool           // the write function was called; false means the pool skipped the instance
	err     *piholeFailure // nil when the write succeeded
	callErr error          // what the call returned, for the audit row
}

func (o outcome) ok() bool { return o.err == nil }

// write runs fn for one instance through s.call and reports the outcome. An error that isn't a Pi-hole or instance
// failure (an entry that doesn't exist, a group the Pi-hole doesn't have, a cancelled request) is also returned, and
// the request fails as usual; the caller still audits a write that was attempted, with outcome.callErr.
func (s *Server) write(ctx context.Context, ref instanceRef, fn func(context.Context, *piholeapi.Client) error) (outcome, error) {
	out := outcome{ref: ref}
	err := s.call(ctx, ref, func(ctx context.Context, c *piholeapi.Client) error {
		out.ran = true
		return fn(ctx, c)
	})
	out.callErr = err
	if err == nil {
		return out, nil
	}
	var pf *piholeFailure
	if !errors.As(err, &pf) {
		return out, err
	}
	out.err = pf
	return out, nil
}

// status reports an outcome as the spec's WriteStatus and WriteError.
func (o outcome) status() (gen.WriteStatus, *gen.WriteError) {
	if o.ok() {
		return gen.WriteStatus("ok"), nil
	}
	f := describeFailure(o.err)
	we := &gen.WriteError{Code: f.code, Message: f.message}
	if f.piholeMessage != "" {
		pm := f.piholeMessage
		we.PiholeMessage = &pm
	}
	if o.ran {
		return gen.WriteStatus("failed"), we
	}
	return gen.WriteStatus("skipped"), we
}

// finishWrite decides how a write is answered once every instance has been tried: (false, nil) for a 200 when every
// outcome is ok, (true, nil) for a 207 when they differ, or the first failure, carrying results for details.results,
// when none is ok. results is the operation's list of results, built from the same outcomes.
func (s *Server) finishWrite(ctx context.Context, outs []outcome, results any) (multi bool, err error) {
	var first *piholeFailure
	okCount := 0
	for _, o := range outs {
		if o.ok() {
			okCount++
			continue
		}
		if first == nil {
			first = o.err
		}
	}
	switch {
	case okCount == len(outs):
		return false, nil
	case okCount == 0:
		failed := *first
		failed.Results = results
		return false, &failed
	}
	for _, o := range outs {
		if !o.ok() {
			s.logFailure(info(ctx).r.Pattern, o.err)
		}
	}
	return true, nil
}

// failure is how a *piholeFailure is reported: its HTTP status when it fails the whole request, its code and a
// message safe to show, and Pi-hole's own reason for a rejection. internal is set for an error with no code of its
// own, which is reported only as "internal".
type failure struct {
	status        int
	code          string
	message       string
	piholeMessage string
	internal      bool
}

// describeFailure says how a *piholeFailure is reported. Pi-hole refusing the request's content is the client's
// 400; an instance that can't be used is a 409, as for enabling one; anything else is the Pi-hole failing, a 502. The
// underlying error can name internal addresses, so it goes to the log and the audit log, not to the client; Pi-hole's
// own reason for a rejection is passed on, as text.
func describeFailure(pf *piholeFailure) failure {
	f := failure{status: http.StatusBadGateway, code: instances.Kind(pf.Err)}
	switch f.code {
	case piholeapi.CodeRejected:
		f.status = http.StatusBadRequest
		f.message = fmt.Sprintf("Pi-hole %q refused the request.", pf.Instance)
		var re *piholeapi.RejectedError
		if errors.As(pf.Err, &re) && re.Message != "" {
			f.piholeMessage = re.Message
			f.message = fmt.Sprintf("Pi-hole %q refused the request: %s", pf.Instance, re.Message)
		}
	case piholeapi.CodeUnreachable:
		f.message = fmt.Sprintf("Pi-hole %q didn't respond.", pf.Instance)
	case piholeapi.CodeAuthRejected:
		f.message = fmt.Sprintf("Pi-hole %q refused the app's password. An administrator needs to check it.", pf.Instance)
	case piholeapi.CodeStatusError:
		f.message = fmt.Sprintf("Pi-hole %q answered, but not as expected.", pf.Instance)
	case instances.CodePasswordMissing:
		f.status = http.StatusConflict
		f.message = fmt.Sprintf("Pi-hole %q can't be used yet: its password isn't set. An administrator needs to set it.", pf.Instance)
	case instances.CodeMisconfigured:
		f.status = http.StatusConflict
		f.message = fmt.Sprintf("The settings of Pi-hole %q can't be used. An administrator needs to fix them.", pf.Instance)
	default:
		f.status, f.code, f.message, f.internal = http.StatusInternalServerError, "internal", "Something went wrong.", true
	}
	return f
}

// logFailure logs a failed Pi-hole call: a rejection is the caller's problem, so it is logged at info level.
func (s *Server) logFailure(request string, pf *piholeFailure) {
	code := instances.Kind(pf.Err)
	level := s.Logger.Warn
	if code == piholeapi.CodeRejected {
		level = s.Logger.Info
	}
	level("pi-hole call failed", "instance", pf.Instance, "request", request, "code", code, "err", pf.Err)
}

// resultsOf builds an operation's results from its outcomes, in order; build fills in each result, including an ok
// result's own fields (the entry as saved, say).
func resultsOf[T any](outs []outcome, build func(o outcome, status gen.WriteStatus, we *gen.WriteError) T) []T {
	out := make([]T, 0, len(outs))
	for _, o := range outs {
		st, we := o.status()
		out = append(out, build(o, st, we))
	}
	return out
}
