// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/config"
)

const healthTimeout = 3 * time.Second

// cmdHealthcheck is `pihole-rbac healthcheck`: it asks the running server's /healthz for "ok" and fails otherwise.
// It exists because the distroless image has no curl or wget for Docker's HEALTHCHECK.
func cmdHealthcheck(args []string) error {
	if len(args) != 0 {
		return errors.New("healthcheck takes no arguments")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	url, err := healthURL(cfg.Listen)
	if err != nil {
		return err
	}
	return checkHealth(url)
}

// healthURL turns the listen address into a loopback URL: a wildcard address is reached on loopback, of the same IP
// family; a specific address or host name is used as it is.
func healthURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("%sLISTEN: %w", config.Prefix, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func checkHealth(url string) error {
	client := &http.Client{
		Timeout: healthTimeout,
		// No proxy: HTTP_PROXY set for the app's outbound requests mustn't send a loopback check elsewhere.
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("unhealthy: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("unhealthy: %s answered %s", url, resp.Status)
	}
	return nil
}
