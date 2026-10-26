// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/logging"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/spa"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/updates"
	"github.com/Kate-0713/pihole-rbac/web"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
		// On an LXC install, root's commands that touch the data directory run as the service user.
		if err := reexecAsService(cmd, args[1:]); err != nil {
			return err
		}
	}
	switch cmd {
	case "serve":
		return serve()
	case "version", "--version", "-v":
		fmt.Println(versionText())
		return nil
	case "setup":
		return cmdSetup(args[1:])
	case "user":
		return cmdUser(args[1:])
	case "rotate-key":
		return cmdRotateKey(args[1:])
	case "import-json":
		return cmdImportJSON(args[1:])
	case "healthcheck":
		return cmdHealthcheck(args[1:])
	case "update":
		return cmdUpdate(args[1:])
	case "updater":
		return cmdUpdater(args[1:])
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: pihole-rbac help)", cmd)
	}
}

const usage = `usage: pihole-rbac [command]

commands:
  serve                        run the server (the default)
  setup [--print-token]        show whether first-run setup is open; --print-token makes a new setup token
  user reset-admin <username>  break-glass recovery: set a local admin's password (read from the terminal or stdin),
                               enable the account and give it the admin role, creating it if needed
  rotate-key --old-key-file <path>
                               re-encrypt the stored secrets (instance passwords, the LDAP bind password, notification
                               channel secrets) from the old master key in the file to the new one in
                               PIHOLE_RBAC_SECRET_KEY; then reload secrets or restart
  import-json --config <config.json> [--permissions <file>] [--users <file>] [--instance-name <name>]
              [--time-zone <zone>] [--offline] [--apply]
                               show what would be imported from v1's files; --apply imports it into a new database
  update [--no-wait] [vX.Y.Z]  LXC installs: update to the latest release, or to the one given (a prerelease only
                               when named), and follow the update until it finishes
  updater                      carry out a pending update request; run as root by pihole-rbac-update.service
  healthcheck                  exit 0 if the server on PIHOLE_RBAC_LISTEN answers /healthz, 1 otherwise
  version                      print the version, build details and source location

On an LXC install, setup, user, rotate-key, import-json and update run as root (sudo pihole-rbac ...) re-run
themselves as the pihole-rbac user with /etc/pihole-rbac/env, so files they create keep the right owner. File paths
given to rotate-key and import-json must be readable by that user.
`

// versionText is checked by CI and the release build: a release must report "frontend: embedded".
func versionText() string {
	frontend := "not built"
	if _, built := web.Dist(); built {
		frontend = "embedded"
	}
	text := buildinfo.String() + "\nfrontend: " + frontend + "\nsource: " + buildinfo.Source + " (" + buildinfo.License + ")"
	if release.TestBuild {
		text += "\nTEST BUILD (updatertest): releases can come from PIHOLE_RBAC_TEST_RELEASES_URL; never deploy this binary"
	}
	return text
}

// loadFrontend returns the embedded SPA, or nil for a binary built without it, which then serves a placeholder page.
func loadFrontend(logger *slog.Logger) (*spa.Handler, error) {
	dist, built := web.Dist()
	if !built {
		logger.Warn("frontend not built: serving a placeholder page; build with make build or .\\build.ps1 build")
		return nil, nil
	}
	return spa.New(dist)
}

func serve() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	// stdout, plus a file per day when PIHOLE_RBAC_LOG_DIR is set. Closed last, so shutdown is logged to the file.
	logs, err := logging.Open(logging.Options{Dir: cfg.LogDir, RetentionDays: cfg.LogRetentionDays, Level: cfg.LogLevel})
	if err != nil {
		return err
	}
	defer logs.Close()
	logger := logs.Logger
	slog.SetDefault(logger)

	// Secrets before the database: a misconfigured secret should stop startup before any migration runs.
	sec, err := secrets.Load(secrets.Options{DataDir: cfg.DataDir})
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	logSecrets(logger, sec)

	frontend, err := loadFrontend(logger)
	if err != nil {
		return err
	}

	// SIGTERM is what systemd and Docker send; os.Interrupt covers Ctrl+C on Windows and Linux.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, store.Options{DataDir: cfg.DataDir, Logger: logger})
	if err != nil {
		return err
	}
	defer st.Close()

	if err := announceSetup(ctx, st, logger); err != nil {
		return err
	}
	auditLog := audit.NewLogger(logs.Writer)

	// The login methods, LDAP settings and bind password, and the login chain built from them. Saving them through the
	// API rebuilds the chain and the recheck's directory without a restart.
	sessions := auth.NewSessions(st, sec.SessionKey, auth.SessionOptions{
		CookieSecure:   cfg.CookieSecure,
		TrustedProxies: cfg.TrustedProxies,
	})
	login := &loginsettings.Service{
		Store: st, Audit: auditLog, Secrets: sec, CAFile: cfg.LDAPCAFile, Logger: logger, Sessions: sessions,
	}
	if err := login.Load(ctx); err != nil {
		return err
	}
	byIP, byUser := api.DefaultLoginLimits()
	// One Pi-hole client per enabled instance. Closing the pool logs every client out of its Pi-hole, so sessions
	// don't hold Pi-hole's API seats after a restart.
	pool := instances.New(instances.Options{Passwords: sec, Logger: logger})
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(closeCtx)
	}()
	instanceService := &instances.Service{Store: st, Audit: auditLog, Pool: pool}
	if err := instanceService.LoadPool(ctx); err != nil {
		return err
	}
	go pool.Run(ctx)
	// Mirrored groups are compared at startup, every few minutes, and soon after a write through them.
	drift := &instances.Drift{Service: instanceService, Logger: logger}
	go drift.Run(ctx)

	// Notification channels: every audit entry reaches the notifier once its transaction has committed, and it sends
	// to the channels that want it in the background. A guard message that can't be delivered is audited.
	notifier := &notify.Notifier{Logger: logger}
	channels := &notifications.Service{Store: st, Audit: auditLog, Secrets: sec, Notifier: notifier, Logger: logger}
	notifier.Failed = channels.GuardFailed
	if err := channels.Reload(ctx); err != nil {
		return err
	}
	auditLog.SetSink(notifier.Notify)
	go notifier.Run(ctx)

	// Client reset. A run the app was in the middle of when it last stopped is marked failed first, since only one
	// run can be in progress at a time and nothing is running that one any more.
	resets := &clientreset.Service{
		Store: st, Audit: auditLog, Instances: instanceService, Protected: channels.ProtectedFor, Logger: logger,
	}
	if _, err := resets.FailInterrupted(ctx); err != nil {
		return err
	}

	// The daily update check, update requests for the LXC updater, and announcing how each update ended: at once, so
	// a version that has just been installed reports itself, then every minute.
	var releases updates.Releases
	if cfg.UpdateCheck {
		releases = release.NewClient(time.Minute)
	}
	updateService := &updates.Service{
		Store: st, Audit: auditLog, Releases: releases, Install: updates.Install(cfg.Install), Logger: logger,
	}
	go updateService.Run(ctx)

	server := api.New(api.Options{
		Store:          st,
		Sessions:       sessions,
		Auth:           login.Authenticator(),
		LoginSettings:  login,
		Notifications:  channels,
		ClientReset:    resets,
		Updates:        updateService,
		Audit:          auditLog,
		Secrets:        sec,
		Instances:      instanceService,
		Drift:          drift,
		Roles:          &rbac.Manager{Store: st, Audit: auditLog},
		TrustedProxies: cfg.TrustedProxies,
		LoginByIP:      byIP,
		LoginByUser:    byUser,
		Frontend:       frontend,
		Logger:         logger,
		Restart:        stop, // the same clean shutdown as SIGTERM; systemd or Docker starts the app again
	})
	go pruneSessions(ctx, sessions, logger)
	// Audit rows older than the retention go at startup, daily, and soon after the retention is changed.
	auditPruner := &audit.Pruner{Store: st, Audit: auditLog, Retention: login.AuditRetentionDays, Logger: logger}
	login.RetentionChanged = auditPruner.Poke
	go auditPruner.Run(ctx)
	// Client reset runs every target with rules daily at the time set in the general settings, while it is on.
	scheduler := &clientreset.Scheduler{Service: resets, Schedule: func() clientreset.Schedule {
		return resetSchedule(login.ResetSchedule())
	}}
	go scheduler.Run(ctx)
	rechecker := &auth.Rechecker{
		Store:     st,
		Audit:     auditLog,
		Directory: login.Directory,
		Logger:    logger,
	}
	go rechecker.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.Listen, "version", buildinfo.Version, "data_dir", cfg.DataDir, "log_dir", cfg.LogDir,
			"install", cfg.Install, "update_check", cfg.UpdateCheck)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// pruneSessions deletes expired and idle sessions every 15 minutes until ctx ends.
func pruneSessions(ctx context.Context, sessions *auth.Sessions, logger *slog.Logger) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := sessions.Prune(ctx); err != nil {
				logger.Warn("pruning sessions failed", "err", err)
			} else if n > 0 {
				logger.Debug("pruned sessions", "count", n)
			}
		}
	}
}

// logSecrets logs which secrets are set and where from. Never values.
func logSecrets(logger *slog.Logger, sec *secrets.Manager) {
	attrs := make([]any, 0, 8)
	for _, s := range sec.Status() {
		state := "missing"
		if s.Set {
			state = string(s.Source)
		}
		attrs = append(attrs, s.Name, state)
	}
	logger.Info("secrets loaded", attrs...)
	if sec.Cipher() == nil {
		logger.Warn("PIHOLE_RBAC_SECRET_KEY is not set: Pi-hole passwords, the LDAP bind password and notification secrets can't be stored until it is")
	}
}

// resetSchedule turns the saved client reset schedule into the scheduler's. The settings are validated when saved
// and loaded, so a time zone that doesn't load can only be a database edited by hand; the scheduler then stays off.
func resetSchedule(r loginsettings.ResetSchedule) clientreset.Schedule {
	loc, err := r.Location()
	if err != nil {
		return clientreset.Schedule{}
	}
	h, m := r.Clock()
	return clientreset.Schedule{Enabled: r.Enabled, Hour: h, Minute: m, Location: loc}
}
