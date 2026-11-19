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
	"github.com/Kate-0713/pihole-rbac/internal/appmetrics"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/buildinfo"
	"github.com/Kate-0713/pihole-rbac/internal/clientoverrides"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/logdestinations"
	"github.com/Kate-0713/pihole-rbac/internal/logging"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/schedules"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/spa"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
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
                               enable the account, give it the admin role and remove its two-factor login, creating
                               the account if needed
  rotate-key --old-key-file <path>
                               re-encrypt the stored secrets (instance passwords, the LDAP bind password, notification
                               channel secrets, two-factor secrets) from the old master key in the file to the new one in
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
	// The metrics that GET /metrics writes, once PIHOLE_RBAC_METRICS_TOKEN is set. A collector that fails (a database
	// read, say) costs its own series and nothing else, and is logged.
	registry := metrics.New()
	registry.ErrorFunc = func(err error) { logger.Warn("collecting metrics", "err", err) }
	metrics.RegisterRuntime(registry, buildinfo.Version)
	auditLog := audit.NewLogger(logs.Writer)
	auditLog.SetMetrics(registry)

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
	pool := instances.New(instances.Options{Passwords: sec, Logger: logger, Metrics: registry})
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
	notifier := &notify.Notifier{Logger: logger, Metrics: registry}
	channels := &notifications.Service{Store: st, Audit: auditLog, Secrets: sec, Notifier: notifier, Logger: logger}
	notifier.Failed = channels.GuardFailed
	if err := channels.Reload(ctx); err != nil {
		return err
	}
	// Log forwarding: a forwarder per enabled destination reads the audit log from its own cursor. The sink only
	// nudges them, so nothing depends on it for delivery; a row nobody nudged for is found at the next poll.
	logDests := &logdestinations.Service{Store: st, Audit: auditLog, Logger: logger, Metrics: registry}
	if err := logDests.Start(ctx); err != nil {
		return err
	}
	auditLog.SetSink(func(e audit.Entry) {
		notifier.Notify(e)
		logDests.Nudge()
	})
	go notifier.Run(ctx)

	// Client reset. A run the app was in the middle of when it last stopped is marked failed first, since only one
	// run can be in progress at a time and nothing is running that one any more.
	// Temporary client group changes come first: client reset leaves the clients they hold alone.
	overrideService := &clientoverrides.Service{
		Store: st, Audit: auditLog, Instances: instanceService, Limits: login.ClientOverrideLimits, Logger: logger,
		ProtectedAdded: func(ctx context.Context, instanceID int64, before, after []string) []string {
			protected, err := channels.ProtectedFor(ctx, instanceID)
			if err != nil {
				logger.Error("reading protected groups", "instance", instanceID, "err", err)
				return nil
			}
			return notifications.ProtectedAdded(before, after, protected)
		},
	}
	resets := &clientreset.Service{
		Store: st, Audit: auditLog, Instances: instanceService, Protected: channels.ProtectedFor, Logger: logger,
		Overridden: overrideService.ActiveClients,
	}
	if _, err := resets.FailInterrupted(ctx); err != nil {
		return err
	}

	// Schedules: blocking turned off, or a Pi-hole group switched, for a window. The scheduler looks at once, so an
	// edge missed while the app was stopped is applied at startup, then every 30 seconds.
	scheduleService := &schedules.Service{
		Store: st, Audit: auditLog, Instances: instanceService, Limits: login.ScheduleLimits, Logger: logger,
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

	// What is read when Prometheus scrapes: instance health, drift, sessions, queues, forwarding lag, client reset
	// runs and whether an update is known. The ones that need the database are cached for 10 seconds.
	appmetrics.Register(registry, appmetrics.Sources{
		Pool: pool, Report: drift.Report, Groups: instanceService.ListGroups, Destinations: logDests.List,
		QueueLength: notifier.QueueLength, Store: st, Lifetimes: sessions.Lifetimes,
		Update: func(ctx context.Context) (known, available bool, err error) {
			if !updateService.CheckEnabled() {
				return false, false, nil
			}
			av, err := updateService.LatestRelease(ctx)
			if err != nil {
				return false, false, err
			}
			return av.Latest != nil, av.UpdateAvailable, nil
		},
	})

	server := api.New(api.Options{
		Store:           st,
		Sessions:        sessions,
		Auth:            login.Authenticator(),
		LoginSettings:   login,
		Notifications:   channels,
		LogDestinations: logDests,
		ClientReset:     resets,
		Schedules:       scheduleService,
		ClientOverrides: overrideService,
		Updates:         updateService,
		Audit:           auditLog,
		Secrets:         sec,
		Instances:       instanceService,
		Drift:           drift,
		Roles:           &rbac.Manager{Store: st, Audit: auditLog, TOTPAvailable: func() bool { return sec.Cipher() != nil }},
		TOTP:            &totp.Service{Store: st, Audit: auditLog, Cipher: sec.Cipher},
		TrustedProxies:  cfg.TrustedProxies,
		LoginByIP:       byIP,
		LoginByUser:     byUser,
		MetricsByIP:     api.DefaultMetricsLimit(),
		MetricsRegistry: registry,
		Frontend:        frontend,
		Logger:          logger,
		Restart:         stop, // the same clean shutdown as SIGTERM; systemd or Docker starts the app again
	})
	go pruneSessions(ctx, sessions, st, logger)
	// Audit rows older than the retention go at startup, daily, and soon after the retention is changed.
	auditPruner := &audit.Pruner{Store: st, Audit: auditLog, Retention: login.AuditRetentionDays, Logger: logger}
	login.RetentionChanged = auditPruner.Poke
	go auditPruner.Run(ctx)
	// Client reset runs every target with rules daily at the time set in the general settings, while it is on.
	scheduler := &clientreset.Scheduler{Service: resets, Schedule: func() clientreset.Schedule {
		return resetSchedule(login.ResetSchedule())
	}}
	go scheduler.Run(ctx)
	go (&schedules.Scheduler{Service: scheduleService}).Run(ctx)
	// Temporary client group changes are put back when their time is up: at once for any that ended while the app
	// was stopped, then every 30 seconds, with the ones that failed retried each time.
	go (&clientoverrides.Scheduler{Service: overrideService}).Run(ctx)
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

// pruneSessions deletes expired and idle sessions, and API tokens revoked or expired more than 30 days ago, every 15
// minutes until ctx ends.
func pruneSessions(ctx context.Context, sessions *auth.Sessions, st *store.Store, logger *slog.Logger) {
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
			if n, err := rbac.PruneTokens(ctx, st, time.Now()); err != nil {
				logger.Warn("pruning API tokens failed", "err", err)
			} else if n > 0 {
				logger.Debug("pruned API tokens", "count", n)
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
