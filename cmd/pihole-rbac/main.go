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
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/spa"
	"github.com/Kate-0713/pihole-rbac/internal/store"
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
  version                      print the version, build details and source location
`

// versionText is checked by CI and the release build: a release must report "frontend: embedded".
func versionText() string {
	frontend := "not built"
	if _, built := web.Dist(); built {
		frontend = "embedded"
	}
	return buildinfo.String() + "\nfrontend: " + frontend + "\nsource: " + buildinfo.Source + " (" + buildinfo.License + ")"
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
	// Replaced by the file-and-stdout logger ported from v1.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
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
	auditLog := audit.NewLogger(os.Stdout)

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

	server := api.New(api.Options{
		Store:          st,
		Sessions:       sessions,
		Auth:           login.Authenticator(),
		LoginSettings:  login,
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
	})
	go pruneSessions(ctx, sessions, logger)
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
		logger.Info("listening", "addr", cfg.Listen, "version", buildinfo.Version, "data_dir", cfg.DataDir)
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
		logger.Warn("PIHOLE_RBAC_SECRET_KEY is not set: notification credentials can't be stored until it is")
	}
}
