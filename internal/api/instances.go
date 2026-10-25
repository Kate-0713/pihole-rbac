// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

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

// ListTargets lists the enabled instances where the session holds at least one permission, with their health, then
// the mirrored groups whose primary is enabled and where it holds at least one, with their enabled members' health.
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
	groups, err := s.Instances.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	enabled := map[int64]instances.Instance{}
	for _, inst := range insts {
		if inst.Enabled {
			enabled[inst.ID] = inst
		}
	}
	mirroredOf := map[int64]instances.Group{}
	for _, g := range groups {
		if g.Mode == rbac.Mirrored {
			for _, id := range g.Members {
				mirroredOf[id] = g
			}
		}
	}

	out := gen.TargetList{Targets: []gen.Target{}}
	for _, inst := range insts {
		t := rbac.InstanceTarget(inst.ID)
		if !inst.Enabled || len(byTarget[t]) == 0 {
			continue
		}
		tj := gen.Target{Id: t.String(), Kind: gen.TargetKindInstance, Name: inst.Name, Health: targetHealth(s.health(inst.ID))}
		if g, ok := mirroredOf[inst.ID]; ok {
			tj.MirroredGroup = &gen.MirroredGroupRef{Id: rbac.GroupTarget(g.ID).String(), Name: g.Name}
		}
		out.Targets = append(out.Targets, tj)
	}
	for _, g := range groups {
		t := rbac.GroupTarget(g.ID)
		primary, ok := enabled[g.Primary]
		if g.Mode != rbac.Mirrored || !ok || len(byTarget[t]) == 0 {
			continue
		}
		members := []gen.TargetMember{{InstanceId: primary.ID, Name: primary.Name, Primary: true, Health: *s.health(primary.ID)}}
		var others []gen.TargetMember
		for _, id := range g.Members {
			if inst, ok := enabled[id]; ok && id != g.Primary {
				others = append(others, gen.TargetMember{InstanceId: id, Name: inst.Name, Health: *s.health(id)})
			}
		}
		slices.SortFunc(others, func(a, b gen.TargetMember) int { return cmp.Compare(a.Name, b.Name) })
		members = append(members, others...)
		tj := gen.Target{Id: t.String(), Kind: gen.TargetKindGroup, Name: g.Name, Members: &members, Health: groupHealth(members)}
		if rep, ok := s.Drift.Report(g.ID); ok && rep.PrimaryOK {
			drifted := rep.Drifted()
			tj.Drifted = &drifted
		}
		out.Targets = append(out.Targets, tj)
	}
	return gen.ListTargets200JSONResponse(out), nil
}

// targetHealth is an instance's health as a target's.
func targetHealth(h *gen.InstanceHealth) *gen.TargetHealth {
	return &gen.TargetHealth{
		State: gen.TargetHealthState(h.State), LastSuccess: h.LastSuccess, LastFailure: h.LastFailure, LastError: h.LastError,
	}
}

// groupHealth is a mirrored group's overall state: up when every enabled member is up, down when every one is down,
// unknown when none has been checked yet, and degraded otherwise.
func groupHealth(members []gen.TargetMember) *gen.TargetHealth {
	count := map[gen.InstanceHealthState]int{}
	for _, m := range members {
		count[m.Health.State]++
	}
	state := gen.TargetHealthState("degraded")
	for _, st := range []gen.InstanceHealthState{"up", "down", "unknown"} {
		if count[st] == len(members) {
			state = gen.TargetHealthState(st)
		}
	}
	return &gen.TargetHealth{State: state}
}

func (s *Server) ListInstances(ctx context.Context, _ gen.ListInstancesRequestObject) (gen.ListInstancesResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	insts, err := s.Instances.List(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.InstanceList{
		Instances:         make([]gen.Instance, len(insts)),
		CanStorePasswords: s.Secrets != nil && s.Secrets.Cipher() != nil,
	}
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

// SetInstancePassword stores a new app password for an instance. The password never appears in a response or the
// audit log.
func (s *Server) SetInstancePassword(ctx context.Context, req gen.SetInstancePasswordRequestObject) (gen.SetInstancePasswordResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	// writeOnly makes the generated field a pointer even though the spec requires it.
	if req.Body.Password == nil {
		return nil, invalid("password", "Enter the new password.")
	}
	inst, err := s.Instances.SetPassword(ctx, actor(ctx), req.Id, secrets.NewValue([]byte(*req.Body.Password)))
	if err != nil {
		return nil, err
	}
	return gen.SetInstancePassword200JSONResponse(s.instanceJSON(inst)), nil
}

func (s *Server) EnableInstance(ctx context.Context, req gen.EnableInstanceRequestObject) (gen.EnableInstanceResponseObject, error) {
	if s.Instances == nil {
		return nil, errNoInstances
	}
	inst, err := s.Instances.SetEnabled(ctx, actor(ctx), req.Id, true)
	if err != nil {
		return nil, err
	}
	// A mirrored group's members changed: check it again.
	s.pokeDrift(ctx, target{t: rbac.InstanceTarget(inst.ID)})
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
	// A mirrored group's members changed: check it again.
	s.pokeDrift(ctx, target{t: rbac.InstanceTarget(inst.ID)})
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
		message = fmt.Sprintf("Pi-hole %q refused the app password.", name)
	case piholeapi.CodeStatusError:
		message = fmt.Sprintf("Pi-hole %q answered, but not as expected.", name)
	case instances.CodePasswordMissing:
		message = fmt.Sprintf("%q has no password yet, so it can't log in to its Pi-hole. Store one on the instances page.", name)
		if envName != "" {
			message = fmt.Sprintf("%q has no password yet, so it can't log in to its Pi-hole. Store one on the instances page, or set %s (a variable added since the app started needs a restart).",
				name, secrets.InstanceVar(envName))
		}
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
	in := instances.Input{Name: b.Name, BaseURL: b.BaseUrl}
	if b.EnvName != nil {
		in.EnvName = *b.EnvName
	}
	if b.Password != nil {
		pw := secrets.NewValue([]byte(*b.Password))
		in.Password = &pw
	}
	if b.TlsMode != nil {
		in.TLSMode = piholeapi.TLSMode(*b.TlsMode)
	}
	if b.CaFile != nil {
		in.CAFile = *b.CaFile
	}
	return in
}

func (s *Server) instanceJSON(inst instances.Instance) gen.Instance {
	source := s.Instances.Pool.PasswordSource(inst)
	out := gen.Instance{
		Id: inst.ID, Name: inst.Name, BaseUrl: inst.BaseURL,
		TlsMode: gen.InstanceTlsMode(inst.TLSMode), Enabled: inst.Enabled, CreatedAt: inst.CreatedAt.UTC(),
		PasswordSource: gen.InstancePasswordSource(source), PasswordSet: source != instances.SourceNone,
	}
	if inst.EnvName != "" {
		env, variable := inst.EnvName, secrets.InstanceVar(inst.EnvName)
		out.EnvName, out.PasswordVariable = &env, &variable
	}
	if inst.CAFile != "" {
		ca := inst.CAFile
		out.CaFile = &ca
	}
	if !inst.Password.IsZero() {
		at, by := inst.Password.UpdatedAt.UTC(), inst.Password.UpdatedBy
		out.PasswordUpdatedAt, out.PasswordUpdatedBy = &at, &by
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
