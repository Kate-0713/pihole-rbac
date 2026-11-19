// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/logdestinations"
)

var errNoLogDestinations = errors.New("api: no log destinations service configured")

// The handlers translate between the API's shapes and logdestinations.Service, which checks logging.manage inside
// each change, applies the rules and writes the audit rows. None of these is open to API tokens.

func logDestinationJSON(d logdestinations.Destination) gen.LogDestination {
	st := gen.LogDestinationStatus{
		State:    gen.LogDestinationStatusState(d.Status.State),
		Behind:   d.Status.Behind,
		Delivery: gen.LogDestinationStatusDelivery(d.Status.Delivery),
	}
	if !d.Status.LastSentAt.IsZero() {
		st.LastSentAt = ptr(d.Status.LastSentAt.UTC())
	}
	if d.Status.LastError != "" {
		st.LastError = ptr(d.Status.LastError)
	}
	if !d.Status.FailingSince.IsZero() {
		st.FailingSince = ptr(d.Status.FailingSince.UTC())
	}
	if d.Status.SkippedPruned > 0 {
		st.SkippedPruned = ptr(d.Status.SkippedPruned)
	}
	out := gen.LogDestination{
		Id: d.ID, Name: d.Name, Host: d.Host, Port: d.Port, Transport: gen.LogTransport(d.Transport),
		TlsMode: gen.LogTLSMode(d.TLSMode), Enabled: d.Enabled, CreatedAt: d.CreatedAt.UTC(), CreatedBy: d.CreatedBy,
		UpdatedAt: d.UpdatedAt.UTC(), UpdatedBy: d.UpdatedBy, Status: st,
	}
	if d.CAFile != "" {
		out.CaFile = ptr(d.CAFile)
	}
	return out
}

func logDestinationInput(b *gen.LogDestinationInput, confirm *gen.Confirm) logdestinations.Input {
	in := logdestinations.Input{Name: b.Name, Host: b.Host, Port: b.Port, Enabled: b.Enabled}
	if b.Transport != nil {
		in.Transport = string(*b.Transport)
	}
	if b.TlsMode != nil {
		in.TLSMode = string(*b.TlsMode)
	}
	if b.CaFile != nil {
		in.CAFile = *b.CaFile
	}
	in.Confirm = confirm != nil && *confirm
	return in
}

func (s *Server) ListLogDestinations(ctx context.Context, _ gen.ListLogDestinationsRequestObject) (gen.ListLogDestinationsResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	list, err := s.LogDestinations.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.LogDestinationList{Destinations: make([]gen.LogDestination, 0, len(list))}
	for _, d := range list {
		out.Destinations = append(out.Destinations, logDestinationJSON(d))
	}
	return gen.ListLogDestinations200JSONResponse(out), nil
}

func (s *Server) GetLogDestination(ctx context.Context, req gen.GetLogDestinationRequestObject) (gen.GetLogDestinationResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	d, err := s.LogDestinations.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetLogDestination200JSONResponse(logDestinationJSON(d)), nil
}

func (s *Server) CreateLogDestination(ctx context.Context, req gen.CreateLogDestinationRequestObject) (gen.CreateLogDestinationResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	d, err := s.LogDestinations.Create(ctx, actor(ctx), logDestinationInput(req.Body, req.Params.Confirm))
	if err != nil {
		return nil, err
	}
	return gen.CreateLogDestination201JSONResponse(logDestinationJSON(d)), nil
}

func (s *Server) UpdateLogDestination(ctx context.Context, req gen.UpdateLogDestinationRequestObject) (gen.UpdateLogDestinationResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	d, err := s.LogDestinations.Update(ctx, actor(ctx), req.Id, logDestinationInput(req.Body, req.Params.Confirm))
	if err != nil {
		return nil, err
	}
	return gen.UpdateLogDestination200JSONResponse(logDestinationJSON(d)), nil
}

func (s *Server) DeleteLogDestination(ctx context.Context, req gen.DeleteLogDestinationRequestObject) (gen.DeleteLogDestinationResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	if err := s.LogDestinations.Delete(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteLogDestination204Response{}, nil
}

func (s *Server) TestLogDestination(ctx context.Context, req gen.TestLogDestinationRequestObject) (gen.TestLogDestinationResponseObject, error) {
	if s.LogDestinations == nil {
		return nil, errNoLogDestinations
	}
	r, err := s.LogDestinations.Test(ctx, actor(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	out := gen.LogDestinationTestResult{Ok: r.OK, Message: r.Message}
	if r.Code != "" {
		out.Code = ptr(r.Code)
	}
	return gen.TestLogDestination200JSONResponse(out), nil
}
