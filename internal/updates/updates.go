// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package updates is the app's side of updating: the daily check for a new release, update requests for the LXC
// updater, and announcing how each request ended. The app never updates itself: on LXC a request is a row in
// update_requests and a touched file, which the root updater (pihole-rbac updater) picks up; on Docker and anything
// else the app only says what to run.
package updates

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	// SettingsKey is the settings row holding the last check's result and the last announced request.
	SettingsKey = "update"

	// RequestFile is the file pihole-rbac-update.path watches. It lives in the service's RuntimeDirectory.
	RequestFile = "/run/pihole-rbac/update.request"

	// CheckInterval is how often the update check runs; each process adds its own jitter of up to an hour either way.
	CheckInterval = 24 * time.Hour
	checkJitter   = time.Hour
	// A first check (or one overdue after a long stop) waits a few minutes after startup, so a restart loop can't
	// hammer GitHub.
	firstCheckMin = time.Minute
	firstCheckMax = 5 * time.Minute
	// minCheckGap stops "check now" from asking GitHub more than once a minute.
	minCheckGap  = time.Minute
	checkTimeout = 30 * time.Second

	// A pending request the updater hasn't taken within PendingTimeout, or a running one not finished within
	// RunningTimeout, is marked failed so it doesn't block later requests.
	PendingTimeout = 10 * time.Minute
	RunningTimeout = time.Hour

	// History is how many requests the status lists.
	History = 10

	tick = time.Minute
)

// Install is how the app was installed (PIHOLE_RBAC_INSTALL).
type Install string

const (
	InstallLXC    Install = config.InstallLXC
	InstallDocker Install = config.InstallDocker
	InstallOther  Install = config.InstallOther
)

// Releases finds the latest release. *release.Client is one.
type Releases interface {
	Latest(ctx context.Context) (release.Release, error)
}

// Actor is whoever asks for an update: a user from the API, or the command line.
type Actor struct {
	UserID   int64 // 0 for the command line
	Username string
	IP       string
}

// Service checks for releases, takes update requests and announces their outcomes.
type Service struct {
	Store *store.Store
	Audit *audit.Logger
	// Releases is asked for the latest release. nil turns the check off (PIHOLE_RBAC_UPDATE_CHECK=false).
	Releases Releases
	Install  Install
	// RequestFile is the file touched for the updater; empty means RequestFile.
	RequestFile string
	// Current is the running version; nil means release.Current.
	Current func() (release.Version, bool)
	Now     func() time.Time // nil means time.Now
	Logger  *slog.Logger

	checkMu sync.Mutex // one check at a time
}

// state is the "update" settings row.
type state struct {
	CheckedAt   int64  `json:"checked_at,omitempty"` // Unix ms of the last check, successful or not
	Latest      string `json:"latest,omitempty"`     // the latest release's tag; empty when there is none
	PublishedAt int64  `json:"published_at,omitempty"`
	CheckError  string `json:"check_error,omitempty"` // why the last check failed; the release found before it is kept
	// AnnouncedThrough is the highest update request ID whose outcome has been audited.
	AnnouncedThrough int64 `json:"announced_through,omitempty"`
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) current() (release.Version, bool) {
	if s.Current != nil {
		return s.Current()
	}
	return release.Current()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Service) requestFile() string {
	if s.RequestFile != "" {
		return s.RequestFile
	}
	return RequestFile
}

// CheckEnabled reports whether the update check is on.
func (s *Service) CheckEnabled() bool { return s.Releases != nil }

func loadState(ctx context.Context, q *db.Queries) (state, error) {
	var st state
	row, err := q.GetSetting(ctx, SettingsKey)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal([]byte(row.Value), &st); err != nil {
		return state{}, fmt.Errorf("settings %q: %w", SettingsKey, err)
	}
	return st, nil
}

func saveState(ctx context.Context, q *db.Queries, st state, at time.Time) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return q.UpsertSetting(ctx, db.UpsertSettingParams{
		Key: SettingsKey, Value: string(b), UpdatedAt: store.Millis(at), UpdatedBy: audit.SystemUser,
	})
}

// updateState changes the state row in its own transaction.
func (s *Service) updateState(ctx context.Context, change func(*state)) error {
	return s.Store.WithTx(ctx, func(q *db.Queries) error {
		st, err := loadState(ctx, q)
		if err != nil {
			return err
		}
		change(&st)
		return saveState(ctx, q, st, s.now())
	})
}

// Check asks GitHub for the latest release and stores the answer. Unless force is set it does nothing when the last
// check was under a minute ago. A failed check is stored as such (keeping the release found before) and isn't an
// error; only a database failure is. With the check off, it does nothing.
func (s *Service) Check(ctx context.Context, force bool) error {
	if !s.CheckEnabled() {
		return nil
	}
	s.checkMu.Lock()
	defer s.checkMu.Unlock()

	st, err := loadState(ctx, s.Store.Read())
	if err != nil {
		return err
	}
	if !force && st.CheckedAt != 0 && s.now().Sub(store.FromMillis(st.CheckedAt)) < minCheckGap {
		return nil
	}

	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	rel, err := s.Releases.Latest(cctx)
	if ctx.Err() != nil {
		return ctx.Err() // shutting down: not a result worth storing
	}
	return s.updateState(ctx, func(st *state) {
		st.CheckedAt = store.Millis(s.now())
		switch {
		case errors.Is(err, release.ErrNoRelease):
			st.Latest, st.PublishedAt, st.CheckError = "", 0, ""
		case err != nil:
			st.CheckError = err.Error()
			s.logger().Warn("update check failed", "err", err)
		default:
			st.Latest, st.CheckError = rel.Version.Tag(), ""
			st.PublishedAt = 0
			if !rel.PublishedAt.IsZero() {
				st.PublishedAt = store.Millis(rel.PublishedAt)
			}
		}
	})
}

// Request is one update request as the System page shows it.
type Request struct {
	ID            int64
	RequestedAt   time.Time
	RequestedBy   string
	TargetVersion string // empty for the latest release
	Status        string // pending, running, done, failed or rolled_back
	Log           string
	FinishedAt    time.Time // zero until finished
}

func requestOf(r db.UpdateRequest) Request {
	out := Request{
		ID: r.ID, RequestedAt: store.FromMillis(r.RequestedAt), RequestedBy: r.RequestedByName,
		TargetVersion: r.TargetVersion.String, Status: r.Status, Log: r.Log,
	}
	if r.FinishedAt.Valid {
		out.FinishedAt = store.FromMillis(r.FinishedAt.Int64)
	}
	return out
}

// Active reports whether the request is still waiting or being carried out.
func (r Request) Active() bool { return r.Status == "pending" || r.Status == "running" }

// Status is everything the System page shows about updates.
type Status struct {
	Current      string // the running version as built ("dev" for a development build)
	Development  bool   // the running version can't be compared with releases
	Install      Install
	CheckEnabled bool
	CheckedAt    time.Time // zero if never checked
	CheckError   string
	Latest       *release.Version // nil when not known, or when no release has been published
	PublishedAt  time.Time
	// UpdateAvailable: the latest release is newer than the running version.
	UpdateAvailable bool
	// CanRequest: an update can be requested now (an LXC install with no request pending or running).
	CanRequest bool
	Requests   []Request // newest first
}

// Status reads the update status. It changes nothing.
func (s *Service) Status(ctx context.Context, buildVersion string) (Status, error) {
	q := s.Store.Read()
	st, err := loadState(ctx, q)
	if err != nil {
		return Status{}, err
	}
	rows, err := q.ListUpdateRequests(ctx, History)
	if err != nil {
		return Status{}, err
	}
	cur, ok := s.current()
	out := Status{
		Current: buildVersion, Development: !ok, Install: s.Install, CheckEnabled: s.CheckEnabled(),
		CheckError: st.CheckError, Requests: make([]Request, 0, len(rows)),
	}
	if st.CheckedAt != 0 {
		out.CheckedAt = store.FromMillis(st.CheckedAt)
	}
	if v, err := release.ParseTag(st.Latest); err == nil {
		out.Latest = &v
		if st.PublishedAt != 0 {
			out.PublishedAt = store.FromMillis(st.PublishedAt)
		}
		out.UpdateAvailable = ok && v.Compare(cur) > 0
	}
	active := false
	for _, r := range rows {
		req := requestOf(r)
		active = active || req.Active()
		out.Requests = append(out.Requests, req)
	}
	out.CanRequest = s.Install == InstallLXC && ok && !active
	return out, nil
}

func conflict(format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf(format, args...)}
}

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

// Request records an update request for the updater and touches the file it watches. target is a tag such as
// "v2.1.0" or "v2.1.0-rc.1", or empty for the latest release. Refusals are *rbac.Error: validation_failed for a
// target that isn't a version or isn't newer than the running one, conflict when this install can't be updated from
// the app or another request is pending or running. The request is audited in the same transaction.
func (s *Service) Request(ctx context.Context, actor Actor, target string) (Request, error) {
	switch s.Install {
	case InstallLXC:
	case InstallDocker:
		return Request{}, conflict("This app runs in Docker, where it never updates itself. On the Docker host, run " +
			"docker compose pull and then docker compose up -d.")
	default:
		return Request{}, conflict("Updating from the app needs the LXC install, whose updater service carries it out. " +
			"Install the new release the way this one was installed.")
	}
	cur, ok := s.current()
	if !ok {
		return Request{}, conflict("This is a development build, which can't be compared with releases, so it can't be " +
			"updated from the app. Install a release with install.sh.")
	}
	var targetVersion sql.NullString
	detailVersion := "latest"
	if target != "" {
		v, err := release.ParseTag(target)
		if err != nil {
			return Request{}, validation("target_version", "%q isn't a version: give a release tag such as v2.1.0 or v2.1.0-rc.1, or leave it empty for the latest release.", target)
		}
		if v.Compare(cur) <= 0 {
			return Request{}, validation("target_version", "%s isn't newer than the running %s.", v.Tag(), cur.Tag())
		}
		targetVersion = sql.NullString{String: v.Tag(), Valid: true}
		detailVersion = v.Tag()
	}

	now := s.now()
	entry := audit.Entry{
		At: now, UserID: actor.UserID, Username: actor.Username, Action: audit.ActionUpdateRequest,
		Target: "pihole-rbac", IP: actor.IP,
		Detail: map[string]any{"version": detailVersion, "from": cur.Tag(), "summary": "to " + describeTarget(detailVersion)},
	}
	var row db.UpdateRequest
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		if err := s.failStale(ctx, q, now); err != nil {
			return err
		}
		n, err := q.CountActiveUpdateRequests(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return conflict("An update is already pending or running. Wait for it to finish.")
		}
		row, err = q.InsertUpdateRequest(ctx, db.InsertUpdateRequestParams{
			RequestedAt:     store.Millis(now),
			RequestedBy:     sql.NullInt64{Int64: actor.UserID, Valid: actor.UserID != 0},
			RequestedByName: actor.Username,
			TargetVersion:   targetVersion,
		})
		if err != nil {
			return err
		}
		entry.Detail["request_id"] = row.ID
		if _, err := audit.Insert(ctx, q, entry); err != nil {
			return err
		}
		// Last, so a failure rolls the request back. If the commit then fails, the updater finds no pending request
		// and does nothing.
		if err := os.WriteFile(s.requestFile(), []byte(fmt.Sprintf("%d\n", row.ID)), 0o640); err != nil {
			s.logger().Error("writing the update request file", "path", s.requestFile(), "err", err)
			return conflict("The updater couldn't be told about the request: %s can't be written. Run install.sh again "+
				"to put the service and the updater's units back in place.", s.requestFile())
		}
		return nil
	})
	if err != nil {
		return Request{}, err
	}
	s.Audit.Log(entry)
	return requestOf(row), nil
}

func describeTarget(v string) string {
	if v == "latest" {
		return "the latest release"
	}
	return v
}

func (s *Service) failStale(ctx context.Context, q *db.Queries, now time.Time) error {
	n, err := q.FailStaleUpdateRequests(ctx, db.FailStaleUpdateRequestsParams{
		Now: sql.NullInt64{Int64: store.Millis(now), Valid: true},
		Message: fmt.Sprintf("%s Marked failed by the app: the updater didn't pick this request up within %s, or didn't "+
			"finish it within %s. Check that pihole-rbac-update.path is installed and enabled (run install.sh again), "+
			"and see journalctl -u pihole-rbac-update.\n",
			now.UTC().Format(time.RFC3339), PendingTimeout, RunningTimeout),
		PendingBefore: store.Millis(now.Add(-PendingTimeout)),
		RunningBefore: store.Millis(now.Add(-RunningTimeout)),
	})
	if n > 0 {
		s.logger().Warn("update requests marked failed: the updater didn't handle them", "count", n)
	}
	return err
}

// Announce marks stale requests failed, then writes an audit entry, as SystemUser, for each finished request not
// announced yet (update_done, update_failed or update_rolled_back), so notification rules can send it. It runs at
// startup, when the new version has just come up, and every minute.
func (s *Service) Announce(ctx context.Context) error {
	now := s.now()
	var entries []audit.Entry
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		entries = nil
		if err := s.failStale(ctx, q, now); err != nil {
			return err
		}
		st, err := loadState(ctx, q)
		if err != nil {
			return err
		}
		rows, err := q.ListFinishedUpdateRequestsAfter(ctx, st.AnnouncedThrough)
		if err != nil || len(rows) == 0 {
			return err
		}
		for _, r := range rows {
			e := s.outcome(r, now)
			if _, err := audit.Insert(ctx, q, e); err != nil {
				return err
			}
			entries = append(entries, e)
			st.AnnouncedThrough = r.ID
		}
		return saveState(ctx, q, st, now)
	})
	if err != nil {
		return err
	}
	for _, e := range entries {
		s.Audit.Log(e)
	}
	return nil
}

// outcome is the audit entry announcing a finished request.
func (s *Service) outcome(r db.UpdateRequest, now time.Time) audit.Entry {
	version := "latest"
	if r.TargetVersion.Valid {
		version = r.TargetVersion.String
	}
	e := audit.Entry{
		At: now, Username: audit.SystemUser, Target: "pihole-rbac",
		Detail: map[string]any{"request_id": r.ID, "version": version, "requested_by": r.RequestedByName},
	}
	switch r.Status {
	case "done":
		e.Action = audit.ActionUpdateDone
		// The new version is the one running now, unless another update has happened since.
		if cur, ok := s.current(); ok {
			e.Detail["summary"] = "now running " + cur.Tag()
		} else {
			e.Detail["summary"] = "to " + describeTarget(version)
		}
	case "rolled_back":
		e.Action = audit.ActionUpdateRolledBack
		e.Detail["summary"] = "to " + describeTarget(version)
		e.Detail["error_code"] = "rolled_back"
		e.Err = errors.New(lastLine(r.Log, "the new version didn't become healthy, so the previous one was restored"))
	default:
		e.Action = audit.ActionUpdateFailed
		e.Detail["summary"] = "to " + describeTarget(version)
		e.Detail["error_code"] = "update_failed"
		e.Err = errors.New(lastLine(r.Log, "the update failed"))
	}
	return e
}

// lastLine is the last non-empty line of an updater log, which says why it stopped, or def.
// The updater starts each line with the UTC time ("12:04:05 "), which the audit entry has already.
func lastLine(log, def string) string {
	lines := strings.Split(strings.TrimSpace(log), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 9 && l[8] == ' ' {
		if _, err := time.Parse("15:04:05", l[:8]); err == nil {
			l = strings.TrimSpace(l[9:])
		}
	}
	if l != "" {
		return l
	}
	return def
}

// Run announces finished requests at once and then every minute, and runs the update check: a few minutes after
// startup if it has never run or is overdue, then every CheckInterval with this process's jitter. It returns when
// ctx ends.
func (s *Service) Run(ctx context.Context) {
	if err := s.Announce(ctx); err != nil {
		s.logger().Error("announcing finished updates", "err", err)
	}
	jitter := time.Duration(rand.Int64N(int64(2*checkJitter))) - checkJitter
	startDelay := firstCheckMin + time.Duration(rand.Int64N(int64(firstCheckMax-firstCheckMin)))
	started := s.now()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Announce(ctx); err != nil && ctx.Err() == nil {
			s.logger().Error("announcing finished updates", "err", err)
		}
		if !s.CheckEnabled() {
			continue
		}
		st, err := loadState(ctx, s.Store.Read())
		if err != nil {
			s.logger().Error("reading the update check state", "err", err)
			continue
		}
		if s.now().Before(nextCheck(st, started, startDelay, jitter)) {
			continue
		}
		if err := s.Check(ctx, false); err != nil && ctx.Err() == nil {
			s.logger().Error("update check", "err", err)
		}
	}
}

// nextCheck is when the update check is next due: CheckInterval plus jitter after the last check, but never sooner
// than startDelay after the process started.
func nextCheck(st state, started time.Time, startDelay, jitter time.Duration) time.Time {
	earliest := started.Add(startDelay)
	if st.CheckedAt == 0 {
		return earliest
	}
	due := store.FromMillis(st.CheckedAt).Add(CheckInterval + jitter)
	if due.Before(earliest) {
		return earliest
	}
	return due
}
