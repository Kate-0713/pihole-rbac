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
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
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
	case "help", "--help", "-h":
		fmt.Println("usage: pihole-rbac [serve|version]")
		return nil
	default:
		return fmt.Errorf("unknown command %q (try: serve, version)", cmd)
	}
}

// versionText is checked by CI and the release build: a release must report "frontend: embedded".
func versionText() string {
	frontend := "not built"
	if _, built := web.Dist(); built {
		frontend = "embedded"
	}
	return buildinfo.String() + "\nfrontend: " + frontend + "\nsource: " + buildinfo.Source + " (" + buildinfo.License + ")"
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

	// SIGTERM is what systemd and Docker send; os.Interrupt covers Ctrl+C on Windows and Linux.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, store.Options{DataDir: cfg.DataDir, Logger: logger})
	if err != nil {
		return err
	}
	defer st.Close()

	authn, err := newAuthenticator(ctx, st)
	if err != nil {
		return err
	}
	sessions := auth.NewSessions(st, sec.SessionKey, auth.SessionOptions{
		CookieSecure:   cfg.CookieSecure,
		TrustedProxies: cfg.TrustedProxies,
	})
	byIP, byUser := api.DefaultLoginLimits()
	server := api.New(api.Options{
		Store:          st,
		Sessions:       sessions,
		Auth:           authn,
		Audit:          audit.NewLogger(os.Stdout),
		TrustedProxies: cfg.TrustedProxies,
		LoginByIP:      byIP,
		LoginByUser:    byUser,
		Logger:         logger,
	})
	go pruneSessions(ctx, sessions, logger)

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

// newAuthenticator builds the login chain from the saved login settings. It is swappable so saving new settings can
// replace it without a restart.
func newAuthenticator(ctx context.Context, st *store.Store) (*auth.SwappableAuthenticator, error) {
	settings, err := auth.LoadSettings(ctx, st.Read())
	if err != nil {
		return nil, err
	}
	chain, err := auth.Build(settings.Methods, map[auth.Method]auth.Authenticator{
		auth.MethodLocal: auth.NewLocalAuthenticator(auth.StoreUsers{St: st}),
	})
	if err != nil {
		return nil, fmt.Errorf("login methods: %w", err)
	}
	return auth.NewSwappable(chain), nil
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
