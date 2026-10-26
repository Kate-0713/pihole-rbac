// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/updates"
)

var (
	errNoUpdates = errors.New("api: no updates service configured")
	errNoRestart = errors.New("api: no restart function configured")
)

// GetVersion reports the running build. Any session may ask; the unauthenticated about endpoint never says.
func (s *Server) GetVersion(context.Context, gen.GetVersionRequestObject) (gen.GetVersionResponseObject, error) {
	_, ok := release.Current()
	return gen.GetVersion200JSONResponse{
		Version: buildinfo.Version, Commit: buildinfo.Commit, BuildDate: buildinfo.Date, Development: !ok,
	}, nil
}

// GetUpdateStatus reports the running version, the last check and the latest update requests.
func (s *Server) GetUpdateStatus(ctx context.Context, _ gen.GetUpdateStatusRequestObject) (gen.GetUpdateStatusResponseObject, error) {
	st, err := s.updateStatus(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetUpdateStatus200JSONResponse(st), nil
}

// CheckForUpdate asks GitHub now (at most once a minute) and reports the new status.
func (s *Server) CheckForUpdate(ctx context.Context, _ gen.CheckForUpdateRequestObject) (gen.CheckForUpdateResponseObject, error) {
	if s.Updates == nil {
		return nil, errNoUpdates
	}
	if !s.Updates.CheckEnabled() {
		return gen.CheckForUpdate409JSONResponse(errorBody("conflict",
			"The update check is off (PIHOLE_RBAC_UPDATE_CHECK=false).")), nil
	}
	if err := s.Updates.Check(ctx, false); err != nil {
		return nil, err
	}
	st, err := s.updateStatus(ctx)
	if err != nil {
		return nil, err
	}
	return gen.CheckForUpdate200JSONResponse(st), nil
}

// RequestUpdate records an update request for the LXC updater. Refusals come from the updates service as
// validation_failed or conflict.
func (s *Server) RequestUpdate(ctx context.Context, req gen.RequestUpdateRequestObject) (gen.RequestUpdateResponseObject, error) {
	if s.Updates == nil {
		return nil, errNoUpdates
	}
	ri := info(ctx)
	target := ""
	if req.Body != nil && req.Body.TargetVersion != nil {
		target = strings.TrimSpace(*req.Body.TargetVersion)
	}
	r, err := s.Updates.Request(ctx, updates.Actor{UserID: ri.sess.UserID, Username: ri.sess.Username, IP: ri.ip}, target)
	if err != nil {
		return nil, err
	}
	return gen.RequestUpdate202JSONResponse(updateRequestOut(r)), nil
}

// RestartApp audits the restart, then asks serve to shut down as on SIGTERM. The server finishes this response
// before it stops; systemd or Docker starts the app again.
func (s *Server) RestartApp(ctx context.Context, _ gen.RestartAppRequestObject) (gen.RestartAppResponseObject, error) {
	if s.Restart == nil {
		return nil, errNoRestart
	}
	ri := info(ctx)
	if err := s.Audit.Record(ctx, s.Store, audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: audit.ActionAppRestart, Target: "pihole-rbac", IP: ri.ip,
		Detail: map[string]any{"version": buildinfo.Version},
	}); err != nil {
		return nil, err
	}
	s.Logger.Info("restart requested", "user", ri.sess.Username)
	s.Restart()
	return gen.RestartApp202Response{}, nil
}

func (s *Server) updateStatus(ctx context.Context) (gen.UpdateStatus, error) {
	if s.Updates == nil {
		return gen.UpdateStatus{}, errNoUpdates
	}
	st, err := s.Updates.Status(ctx, buildinfo.Version)
	if err != nil {
		return gen.UpdateStatus{}, err
	}
	out := gen.UpdateStatus{
		CurrentVersion:  st.Current,
		Development:     st.Development,
		Install:         gen.UpdateStatusInstall(st.Install),
		CheckEnabled:    st.CheckEnabled,
		UpdateAvailable: st.UpdateAvailable,
		CanRequest:      st.CanRequest,
		Requests:        make([]gen.UpdateRequest, 0, len(st.Requests)),
	}
	if !st.CheckedAt.IsZero() {
		out.CheckedAt = &st.CheckedAt
	}
	if st.CheckError != "" {
		out.CheckError = &st.CheckError
	}
	if st.Latest != nil {
		out.Latest = &gen.LatestRelease{Version: st.Latest.Tag(), Url: release.PageURL(*st.Latest)}
		if !st.PublishedAt.IsZero() {
			out.Latest.PublishedAt = &st.PublishedAt
		}
	}
	for _, r := range st.Requests {
		out.Requests = append(out.Requests, updateRequestOut(r))
	}
	return out, nil
}

func updateRequestOut(r updates.Request) gen.UpdateRequest {
	out := gen.UpdateRequest{
		Id: r.ID, RequestedAt: r.RequestedAt, RequestedBy: r.RequestedBy,
		Status: gen.UpdateRequestStatus(r.Status), Log: r.Log,
	}
	if r.TargetVersion != "" {
		out.TargetVersion = &r.TargetVersion
	}
	if !r.FinishedAt.IsZero() {
		out.FinishedAt = &r.FinishedAt
	}
	return out
}
