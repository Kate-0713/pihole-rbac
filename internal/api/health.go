// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api holds the HTTP handlers and routing.
package api

import "net/http"

// Healthz is unauthenticated and returns only "ok", for Docker health checks
// and the LXC updater. It must never reveal anything about the install.
func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
}
