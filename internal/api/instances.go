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
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

var errNoInstances = errors.New("api: no instance service configured")

// actor describes the request's user to the service layers, which check permissions again inside their own
// transactions.
func actor(ctx context.Context) rbac.Actor {
	ri := info(ctx)
	return rbac.Actor{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Source: ri.sess.Source, RoleIDs: ri.sess.RoleIDs,
		PublicID: ri.sess.PublicID, IP: ri.ip,
	}
}

// ListTargets lists the enabled instances where the session holds at least one permission, with their health.
func (s *Server) ListTargets(ctx context.Context, _ gen.ListTargetsRequestObject) (gen.ListTargetsResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	byTarget := set.ByTarget()
	insts, err := s.Instances.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.TargetList{Targets: []gen.Target{}}
	for _, inst := range insts {
		t := rbac.InstanceTarget(inst.ID)
		if !inst.Enabled || len(byTarget[t]) == 0 {
			continue
		}
		out.Targets = append(out.Targets, gen.Target{
			Id: t.String(), Kind: gen.TargetKindInstance, Name: inst.Name, Health: s.health(inst.ID),
		})
	}
	return gen.ListTargets200JSONResponse(out), nil
}

func (s *Server) ListInstances(ctx context.Context, _ gen.ListInstancesRequestObject) (gen.ListInstancesResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	insts, err := s.Instances.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.InstanceList{Instances: make([]gen.Instance, len(insts))}
	for i, inst := range insts {
		out.Instances[i] = s.instanceJSON(inst)
	}
	return gen.ListInstances200JSONResponse(out), nil
}

func (s *Server) GetInstance(ctx context.Context, req gen.GetInstanceRequestObject) (gen.GetInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetInstance200JSONResponse(s.instanceJSON(inst)), nil
}

func (s *Server) CreateInstance(ctx context.Context, req gen.CreateInstanceRequestObject) (gen.CreateInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.Create(ctx, actor(ctx), instanceInput(req.Body))
	if err != nil {
		return nil, err
	}
	return gen.CreateInstance201JSONResponse(s.instanceJSON(inst)), nil
}

func (s *Server) UpdateInstance(ctx context.Context, req gen.UpdateInstanceRequestObject) (gen.UpdateInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.Update(ctx, actor(ctx), req.Id, instanceInput(req.Body))
	if err != nil {
		return nil, err
	}
	return gen.UpdateInstance200JSONResponse(s.instanceJSON(inst)), nil
}

func (s *Server) DeleteInstance(ctx context.Context, req gen.DeleteInstanceRequestObject) (gen.DeleteInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	if err := s.Instances.Delete(ctx, actor(ctx), req.Id); err != nil {
		return nil, err
	}
	return gen.DeleteInstance204Response{}, nil
}

func (s *Server) EnableInstance(ctx context.Context, req gen.EnableInstanceRequestObject) (gen.EnableInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.SetEnabled(ctx, actor(ctx), req.Id, true)
	if err != nil {
		return nil, err
	}
	return gen.EnableInstance200JSONResponse(s.instanceJSON(inst)), nil
}

func (s *Server) DisableInstance(ctx context.Context, req gen.DisableInstanceRequestObject) (gen.DisableInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.SetEnabled(ctx, actor(ctx), req.Id, false)
	if err != nil {
		return nil, err
	}
	return gen.DisableInstance200JSONResponse(s.instanceJSON(inst)), nil
}

// TestInstance reports a failed connection test as a result, not as an error of the request.
func (s *Server) TestInstance(ctx context.Context, req gen.TestInstanceRequestObject) (gen.TestInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	err := s.Instances.Test(ctx, actor(ctx), req.Id)
	if err == nil {
		return gen.TestInstance200JSONResponse{Ok: true}, nil
	}
	if instances.Kind(err) == "" || ctx.Err() != nil {
		return nil, err
	}
	inst, gerr := s.Instances.Get(ctx, req.Id)
	if gerr != nil {
		return nil, gerr
	}
	code, msg := instanceFailure(inst.Name, inst.EnvName, err)
	detail := err.Error()
	return gen.TestInstance200JSONResponse{Error: &gen.InstanceTestError{
		Code: gen.InstanceTestErrorCode(code), Message: msg, Detail: &detail,
	}}, nil
}

// testFailed answers an enable or edit refused because the connection test failed: 409 when the test couldn't run
// (no password, unusable settings), 502 when the Pi-hole failed it.
func (s *Server) testFailed(w http.ResponseWriter, te *instances.TestError) {
	code, msg := instanceFailure(te.Instance, te.EnvName, te.Err)
	status := http.StatusBadGateway
	if code == instances.CodePasswordMissing || code == instances.CodeMisconfigured {
		status = http.StatusConflict
	}
	body := errorBody(code, msg)
	details := map[string]any{"instance": te.Instance, "detail": te.Err.Error()}
	body.Error.Details = &details
	writeJSON(w, status, body)
}

// instanceFailure is the error code and a message for the admin when an instance can't be used or its Pi-hole
// failed a call.
func instanceFailure(name, envName string, err error) (code, message string) {
	code = instances.Kind(err)
	switch code {
	case piholeapi.CodeUnreachable:
		message = fmt.Sprintf("Pi-hole %q didn't respond.", name)
	case piholeapi.CodeAuthRejected:
		message = fmt.Sprintf("Pi-hole %q refused the app password in %s.", name, secrets.InstanceVar(envName))
	case piholeapi.CodeStatusError:
		message = fmt.Sprintf("Pi-hole %q answered, but not as expected.", name)
	case instances.CodePasswordMissing:
		message = fmt.Sprintf("%s isn't set, so %q can't log in to its Pi-hole. A variable added since the app started needs a restart.",
			secrets.InstanceVar(envName), name)
	case instances.CodeMisconfigured:
		message = fmt.Sprintf("The settings of %q can't be used.", name)
	default:
		code, message = "internal", "Something went wrong."
	}
	return code, message
}

func instanceInput(b *gen.InstanceInput) instances.Input {
	if b == nil {
		return instances.Input{}
	}
	in := instances.Input{Name: b.Name, BaseURL: b.BaseUrl, EnvName: b.EnvName}
	if b.TlsMode != nil {
		in.TLSMode = piholeapi.TLSMode(*b.TlsMode)
	}
	if b.CaFile != nil {
		in.CAFile = *b.CaFile
	}
	return in
}

func (s *Server) instanceJSON(inst instances.Instance) gen.Instance {
	out := gen.Instance{
		Id: inst.ID, Name: inst.Name, BaseUrl: inst.BaseURL, EnvName: inst.EnvName,
		TlsMode: gen.InstanceTlsMode(inst.TLSMode), Enabled: inst.Enabled, CreatedAt: inst.CreatedAt.UTC(),
		PasswordVariable: secrets.InstanceVar(inst.EnvName),
	}
	if inst.CAFile != "" {
		ca := inst.CAFile
		out.CaFile = &ca
	}
	if s.Secrets != nil {
		_, out.PasswordSet = s.Secrets.InstancePassword(inst.EnvName)
	}
	if inst.Enabled {
		out.Health = s.health(inst.ID)
	}
	return out
}

// health is an enabled instance's health from the pool: unknown if the pool doesn't have it yet.
func (s *Server) health(id int64) *gen.InstanceHealth {
	h, ok := s.Instances.Pool.Health(id)
	if !ok {
		return &gen.InstanceHealth{State: gen.InstanceHealthState(instances.StateUnknown)}
	}
	out := &gen.InstanceHealth{State: gen.InstanceHealthState(h.State)}
	if !h.LastSuccess.IsZero() {
		t := h.LastSuccess.UTC()
		out.LastSuccess = &t
	}
	if !h.LastFailure.IsZero() {
		t := h.LastFailure.UTC()
		out.LastFailure = &t
	}
	if h.LastError != "" {
		e := h.LastError
		out.LastError = &e
	}
	return out
}
