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
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
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
	mux *http.ServeMux
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
		BaseRouter:  s.mux,
		Middlewares: []gen.MiddlewareFunc{s.gate},
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
// refuses requests without a session unless the route is public.
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
		if sess == nil && !publicRoutes[r.Pattern] {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "You need to log in.")
			return
		}

		ri := &reqInfo{w: w, sess: sess, ip: ratelimit.ClientIP(r, s.TrustedProxies)}
		r = r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, ri))
		ri.r = r
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

// responseError handles an error returned by a handler: an unexpected failure, logged in full but reported to the
// client only as "internal".
func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
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
