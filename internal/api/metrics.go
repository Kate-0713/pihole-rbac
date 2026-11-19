// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// DefaultMetricsLimit returns the limiter for wrong tokens on GET /metrics: 10 failures per address in a rolling 15
// minutes, as for logins. It is a limiter of its own, so a scraper with a mistyped token can lock nobody out of
// logging in, whatever address it comes from.
func DefaultMetricsLimit() *ratelimit.Limiter {
	return ratelimit.New(10, 15*time.Minute)
}

// metricsAuth is the gate for GET /metrics. It answers the request itself and returns false when the request is
// refused. In order:
//   - 404 while no token is set, so nothing is exposed until someone chooses to; this counts nothing;
//   - 429 while the address has used its wrong-token allowance, without looking at the token;
//   - 401 for a missing, malformed or wrong token, which counts against the allowance. Exactly one Authorization
//     header is accepted, and it must be a bearer token.
//
// The token is compared in constant time. Sessions, cookies, CSRF and Origin play no part: a scrape is a GET that
// reads nothing about a user, and a personal API token doesn't open it.
func (s *Server) metricsAuth(w http.ResponseWriter, r *http.Request) bool {
	var want secrets.Value
	var set bool
	if s.Secrets != nil {
		want, set = s.Secrets.MetricsToken()
	}
	if !set {
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
		return false
	}

	ip := ratelimit.ClientIP(r, s.TrustedProxies)
	if ok, wait := s.MetricsByIP.Allow(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many failed attempts from this address. Try again later.")
		return false
	}

	var got string
	var found bool
	if h := r.Header.Values("Authorization"); len(h) == 1 {
		got, found = parseBearer(h[0])
	}
	if !found || !want.Equal(secrets.NewValue([]byte(got))) {
		if s.MetricsByIP.Fail(ip) {
			s.Logger.Warn("wrong metrics tokens from one address reached the limit", "ip", ip)
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "The metrics token is missing or wrong.")
		return false
	}
	return true
}

// metricsResponse writes the registry as the response, so the Content-Type is the exposition format's rather than the
// bare text/plain the generated response would set. A write error is the scraper going away; nothing more can be
// said to it, so it is not an error here.
type metricsResponse struct{ reg *metrics.Registry }

func (m metricsResponse) VisitMetricsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", metrics.ContentType)
	_, _ = m.reg.WriteTo(w)
	return nil
}

// Metrics answers a scrape. The gate has already checked the token.
func (s *Server) Metrics(context.Context, gen.MetricsRequestObject) (gen.MetricsResponseObject, error) {
	return metricsResponse{s.MetricsRegistry}, nil
}
