// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/metrics"
)

// apiMetrics are the counters the API keeps. Every field is nil-safe: with no registry they count nothing.
type apiMetrics struct {
	httpRequests *metrics.Counter
	httpDuration *metrics.Histogram
	writes       *metrics.Counter
	tokens       *metrics.Counter
}

func newAPIMetrics(r *metrics.Registry) apiMetrics {
	return apiMetrics{
		httpRequests: r.Counter("pihole_rbac_http_requests_total",
			"Requests answered by the app, by route pattern and status class. Requests no route matches are counted as unmatched.",
			"route", "code_class"),
		httpDuration: r.Histogram("pihole_rbac_http_request_duration_seconds",
			"How long the app took to answer, by route pattern.", metrics.HTTPBuckets, "route"),
		writes: r.Counter("pihole_rbac_writes_total",
			"API write operations on Pi-hole instances by outcome: ok (every instance), partial (some instances failed, answered 207) or failed (none succeeded).",
			"result"),
		tokens: r.Counter("pihole_rbac_api_token_requests_total",
			"Requests carrying an API token, by result: ok, invalid (unknown, malformed or wrong secret), revoked (revoked or owner disabled), expired, suspended, rate_limited, not_allowed (route takes no token), totp_setup_required, forbidden (owner or token lacks tokens.use) or error.",
			"result"),
	}
}

// statusWriter records the status a handler wrote. Unwrap and Flush keep http.ResponseController and streaming working.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// instrument counts a request and times it once next has answered. The route is the mux's pattern, which is a fixed
// set, never the path: a scanner can't make new series.
func (m apiMetrics) instrument(next http.Handler) http.Handler {
	if m.httpRequests == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		began := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		m.httpRequests.Inc(route, codeClass(status))
		m.httpDuration.Observe(time.Since(began).Seconds(), route)
	})
}

func codeClass(status int) string {
	if status < 100 || status > 599 {
		return "other"
	}
	return strconv.Itoa(status/100) + "xx"
}
