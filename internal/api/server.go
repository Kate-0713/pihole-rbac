// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api serves the JSON API defined in api/openapi.yaml. Routing, request decoding and response types are
// generated into internal/api/gen; this package implements the handlers and the checks every request goes through.
package api

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
)

// MaxBodyBytes caps every request body, as in v1.
const MaxBodyBytes = 1 << 20

// ContentSecurityPolicy is sent on every response. script-src gets the hash of the SPA's inline bootstrap script
// once the frontend is served; 'unsafe-inline' is never added to it.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// Options holds the server's dependencies.
type Options struct {
	Store          *store.Store
	Sessions       *auth.Sessions
	Auth           auth.Authenticator
	Audit          *audit.Logger
	Secrets        *secrets.Manager
	Instances      *instances.Service // instance changes, and the client pool for health and secret reloads
	TrustedProxies []netip.Prefix
	LoginByIP      *ratelimit.Limiter // failed logins per client address; nil disables
	LoginByUser    *ratelimit.Limiter // failed logins per username; nil disables
	Logger         *slog.Logger
}

// DefaultLoginLimits returns the v1 login throttles: 10 failures per address and 5 per username in a rolling 15
// minutes.
func DefaultLoginLimits() (byIP, byUser *ratelimit.Limiter) {
	return ratelimit.New(10, 15*time.Minute), ratelimit.New(5, 15*time.Minute)
}

// Server implements gen.StrictServerInterface.
type Server struct {
	Options
	mux       *http.ServeMux
	setupDone atomic.Bool // once true, never false again; until then, the database is asked on each request
}

var _ gen.StrictServerInterface = (*Server)(nil)

// New builds the server and its routes.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	s := &Server{Options: o, mux: http.NewServeMux()}
	strict := gen.NewStrictHandlerWithOptions(s, nil, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  s.requestError,
		ResponseErrorHandlerFunc: s.responseError,
	})
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter:       s.mux,
		Middlewares:      []gen.MiddlewareFunc{s.gate},
		ErrorHandlerFunc: s.paramError,
	})
	s.mux.HandleFunc("/api/", s.apiNotFound)
	return s
}

// Handler returns the server's http.Handler: security headers and the body cap around every route.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if auth.IsHTTPS(r, s.TrustedProxies) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		s.mux.ServeHTTP(w, r)
	})
}

// reqInfo is what the gate learned about a request, for the handlers. Strict handlers only get a context, so it
// travels there.
type reqInfo struct {
	w    http.ResponseWriter
	r    *http.Request
	sess *auth.Session // nil when there is no valid session
	ip   string        // client address, from X-Forwarded-For only behind a trusted proxy

	perms *rbac.Set // resolved on first use; see Server.permissions
}

type reqInfoKey struct{}

func info(ctx context.Context) *reqInfo {
	ri, _ := ctx.Value(reqInfoKey{}).(*reqInfo)
	if ri == nil {
		// Only reachable if a route were registered without the gate.
		panic("api: request didn't pass through the gate")
	}
	return ri
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// gate runs before every generated route (r.Pattern is set by then). For API routes it requires a JSON body on
// state-changing requests, loads the session, checks the Origin and CSRF token on state-changing requests, and
// refuses requests without a session unless the route is public, and refuses sessions that lack the global
// permission the route declares in routePermission. A route missing from that table is refused: fail closed.
func (s *Server) gate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Pattern == "GET /healthz" {
			next.ServeHTTP(w, r)
			return
		}

		unsafe := !isSafeMethod(r.Method)
		if unsafe && r.ContentLength != 0 && !isJSON(r.Header.Get("Content-Type")) {
			writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "The request body must be application/json.")
			return
		}

		if !setupRoutes[r.Pattern] {
			needed, err := s.setupRequired(r.Context())
			if err != nil {
				s.Logger.Error("reading setup state", "err", err)
				writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
				return
			}
			if needed {
				writeError(w, http.StatusServiceUnavailable, "setup_required", "First-run setup hasn't been completed yet.")
				return
			}
		}

		sess, err := s.Sessions.Get(r.Context(), r)
		if err != nil && !errors.Is(err, auth.ErrNoSession) {
			s.Logger.Error("loading session", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
			return
		}

		if unsafe && (!sameOrigin(r, s.TrustedProxies) || !s.Sessions.CheckCSRF(r, sess)) {
			writeError(w, http.StatusForbidden, "csrf_failed", "The request was refused because its CSRF token or origin didn't match. Reload the page and try again.")
			return
		}
		access, declared := routePermission[r.Pattern]
		if !declared {
			s.Logger.Error("route has no declared permission", "pattern", r.Pattern)
			writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
			return
		}
		if sess == nil && access != accessPublic {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "You need to log in.")
			return
		}

		ri := &reqInfo{w: w, sess: sess, ip: ratelimit.ClientIP(r, s.TrustedProxies)}
		r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, ri))
		ri.r = r
		if kind, perm, _ := parseAccess(access); kind == "global" {
			if err := s.requireGlobal(r.Context(), rbac.Permission(perm)); err != nil {
				s.responseError(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

// sameOrigin reports whether the request's Origin (or, without one, its Referer) is the app's own origin. The
// scheme comes from the connection or a trusted proxy's X-Forwarded-Proto, the host from the Host header. A request
// with neither header is refused: browsers send Origin on every state-changing fetch.
func sameOrigin(r *http.Request, trusted []netip.Prefix) bool {
	scheme := "http"
	if auth.IsHTTPS(r, trusted) {
		scheme = "https"
	}
	own := scheme + "://" + r.Host

	origin := r.Header.Get("Origin")
	if origin == "" {
		u, err := url.Parse(r.Header.Get("Referer"))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}
		origin = u.Scheme + "://" + u.Host
	}
	return strings.EqualFold(origin, own)
}

// requestError handles a request body the generated code couldn't decode.
func (s *Server) requestError(w http.ResponseWriter, _ *http.Request, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, http.StatusRequestEntityTooLarge, "validation_failed", "The request body is too large.")
		return
	}
	writeError(w, http.StatusBadRequest, "validation_failed", "The request body isn't valid JSON for this endpoint.")
}

// paramError handles a path parameter the generated code couldn't parse, such as a non-numeric ID. It runs before
// the gate, so it reveals nothing beyond the route's shape.
func (s *Server) paramError(w http.ResponseWriter, _ *http.Request, _ error) {
	w.Header().Set("Cache-Control", "no-store")
	writeError(w, http.StatusBadRequest, "validation_failed", "A value in the URL isn't valid.")
}

// responseError handles an error returned by a handler: a refusal from the rbac package is answered as such (see
// refuse), a failed connection test as a Pi-hole or instance error (see testFailed), and a failed Pi-hole call on a
// target likewise (see piholeFailed); anything else is an unexpected failure, logged in full but reported to the
// client only as "internal".
func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := rbac.AsError(err); ok {
		s.refuse(w, r, e)
		return
	}
	var te *instances.TestError
	if errors.As(err, &te) {
		s.testFailed(w, te)
		return
	}
	var pf *piholeFailure
	if errors.As(err, &pf) {
		s.piholeFailed(w, r, pf)
		return
	}
	s.Logger.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
}

func errorBody(code, message string) gen.Error {
	return gen.Error{Error: gen.ErrorBody{Code: code, Message: message}}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody(code, message))
}

// retryAfterSeconds rounds up, so a client that waits exactly that long is allowed in.
func retryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}
