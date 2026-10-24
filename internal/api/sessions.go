// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	defaultSessionPage = 50
	maxSessionPage     = 200
)

var publicIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// ListSessions lists active sessions: everyone's with sessions.manage (unless mine is set), otherwise the caller's
// own. The cursor is the created time and public ID of the previous page's last session, base64url-encoded.
func (s *Server) ListSessions(ctx context.Context, req gen.ListSessionsRequestObject) (gen.ListSessionsResponseObject, error) {
	ri := info(ctx)
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	limit := defaultSessionPage
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	if limit < 1 || limit > maxSessionPage {
		return nil, invalid("limit", "The limit is 1 to %d.", maxSessionPage)
	}
	var afterCreated int64
	var afterID string
	if req.Params.Cursor != nil && *req.Params.Cursor != "" {
		if afterCreated, afterID, err = decodeCursor(*req.Params.Cursor); err != nil {
			return nil, invalid("cursor", "That cursor isn't one this server gave out.")
		}
	}
	all := set.CanGlobal(rbac.SessionsManage) && !(req.Params.Mine != nil && *req.Params.Mine)
	var userID int64
	if !all {
		userID = ri.sess.UserID
	}
	now := time.Now()
	_, idle := s.Sessions.Lifetimes()
	// One more than asked for says whether there is another page.
	rows, err := s.Store.Read().ListActiveSessions(ctx, db.ListActiveSessionsParams{
		Now: store.Millis(now), IdleCutoff: store.Millis(now.Add(-idle)), UserID: userID,
		AfterCreated: afterCreated, AfterPublicID: afterID, RowLimit: int64(limit + 1),
	})
	if err != nil {
		return nil, err
	}
	out := gen.SessionList{Sessions: []gen.SessionInfo{}, All: all}
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		c := encodeCursor(last.CreatedAt, last.PublicID)
		out.NextCursor = &c
	}
	for _, r := range rows {
		out.Sessions = append(out.Sessions, gen.SessionInfo{
			PublicId:  r.PublicID,
			User:      gen.SessionUser{Id: r.UserID, Username: r.Username, Source: gen.SessionUserSource(r.Source)},
			CreatedAt: store.FromMillis(r.CreatedAt), LastSeenAt: store.FromMillis(r.LastSeenAt),
			ExpiresAt: store.FromMillis(r.ExpiresAt), Ip: r.Ip, UserAgent: r.UserAgent,
			Current: r.PublicID == ri.sess.PublicID,
		})
	}
	return gen.ListSessions200JSONResponse(out), nil
}

func encodeCursor(createdAt int64, publicID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(createdAt, 10) + ":" + publicID))
}

func decodeCursor(c string) (int64, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, "", err
	}
	ms, id, ok := strings.Cut(string(b), ":")
	if !ok || !publicIDPattern.MatchString(id) {
		return 0, "", errors.New("bad cursor")
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil || n <= 0 {
		return 0, "", errors.New("bad cursor")
	}
	return n, id, nil
}

var errSessionNotFound = &rbac.Error{Code: rbac.CodeNotFound, Message: "There's no such session, or it has already ended."}

// RevokeSession ends a session: one of the caller's own, or anyone's with sessions.manage. A session the caller may
// not end is not found, as one that doesn't exist is, so the answer reveals nothing about other users' sessions.
func (s *Server) RevokeSession(ctx context.Context, req gen.RevokeSessionRequestObject) (gen.RevokeSessionResponseObject, error) {
	ri := info(ctx)
	if !publicIDPattern.MatchString(req.PublicId) {
		return nil, errSessionNotFound
	}
	set, err := s.permissions(ctx)
	if err != nil {
		return nil, err
	}
	entry := audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: audit.ActionSessionRevoke, IP: ri.ip,
		Detail: map[string]any{"session": req.PublicId},
	}
	err = s.Store.WithTx(ctx, func(q *db.Queries) error {
		target, err := q.GetSessionByPublicID(ctx, req.PublicId)
		if errors.Is(err, sql.ErrNoRows) {
			return errSessionNotFound
		}
		if err != nil {
			return err
		}
		if target.UserID != ri.sess.UserID && !set.CanGlobal(rbac.SessionsManage) {
			return errSessionNotFound
		}
		entry.Target = "user:" + target.Username
		if _, err := q.DeleteSessionByPublicID(ctx, req.PublicId); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Audit.Log(entry)
	if req.PublicId == ri.sess.PublicID {
		s.Sessions.ClearCookie(ri.w, ri.r)
	}
	return gen.RevokeSession204Response{}, nil
}

func (s *Server) GetGeneralSettings(context.Context, gen.GetGeneralSettingsRequestObject) (gen.GetGeneralSettingsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	return gen.GetGeneralSettings200JSONResponse(generalJSON(s.LoginSettings.General())), nil
}

func (s *Server) SetGeneralSettings(ctx context.Context, req gen.SetGeneralSettingsRequestObject) (gen.SetGeneralSettingsResponseObject, error) {
	if s.LoginSettings == nil {
		return nil, errNoLogin
	}
	g := loginsettings.General{
		SessionLifetimeMinutes: req.Body.SessionLifetimeMinutes, IdleTimeoutMinutes: req.Body.IdleTimeoutMinutes,
	}
	if err := s.LoginSettings.SaveGeneral(ctx, actor(ctx), g); err != nil {
		return nil, err
	}
	return gen.SetGeneralSettings200JSONResponse(generalJSON(s.LoginSettings.General())), nil
}

func generalJSON(v loginsettings.GeneralView) gen.GeneralSettings {
	out := gen.GeneralSettings{SessionLifetimeMinutes: v.SessionLifetimeMinutes, IdleTimeoutMinutes: v.IdleTimeoutMinutes}
	if !v.UpdatedAt.IsZero() {
		at, by := v.UpdatedAt, v.UpdatedBy
		out.UpdatedAt, out.UpdatedBy = &at, &by
	}
	return out
}
