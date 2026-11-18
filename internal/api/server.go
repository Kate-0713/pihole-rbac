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
	"github.com/Kate-0713/pihole-rbac/internal/clientoverrides"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/gravity"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/ratelimit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/schedules"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/spa"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/totp"
	"github.com/Kate-0713/pihole-rbac/internal/updates"
)

// MaxBodyBytes caps every request body, as in v1.
const MaxBodyBytes = 1 << 20

// ContentSecurityPolicy is the policy sent on every response when no frontend is served. With a frontend, script-src
// also lists the hashes of its inline scripts (see contentSecurityPolicy); 'unsafe-inline' is never added to it.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// contentSecurityPolicy adds the given script hashes ('sha256-…') to script-src.
func contentSecurityPolicy(scriptHashes []string) string {
	if len(scriptHashes) == 0 {
		return ContentSecurityPolicy
	}
	return strings.Replace(ContentSecurityPolicy, "script-src 'self'", "script-src 'self' "+strings.Join(scriptHashes, " "), 1)
}

// Options holds the server's dependencies.
type Options struct {
	Store           *store.Store
	Sessions        *auth.Sessions
	Auth            auth.Authenticator
	Audit           *audit.Logger
	Secrets         *secrets.Manager
	Instances       *instances.Service       // instance changes, and the client pool for health and secret reloads
	Drift           *instances.Drift         // mirrored groups' drift reports; nil in tests that don't need them
	Roles           *rbac.Manager            // changes to roles, grants, user roles, LDAP mappings and users
	TOTP            *totp.Service            // two-factor login; New makes one from Store, Audit and Secrets when nil
	LoginSettings   *loginsettings.Service   // login methods, LDAP settings and bind password; nil in tests that don't need them
	Notifications   *notifications.Service   // notification channels; nil in tests that don't need them
	ClientReset     *clientreset.Service     // client reset rules and runs; nil in tests that don't need them
	Schedules       *schedules.Service       // blocking and Pi-hole group schedules; nil in tests that don't need them
	ClientOverrides *clientoverrides.Service // temporary client group changes; nil in tests that don't need them
	Gravity         *gravity.Service         // gravity runs; New makes one from Instances' pool when nil
	Updates         *updates.Service         // the update check and update requests; nil in tests that don't need them
	// Restart asks the process to shut down cleanly, as SIGTERM does, so its service manager starts it again. nil in
	// tests that don't need it.
	Restart        func()
	TrustedProxies []netip.Prefix
	LoginByIP      *ratelimit.Limiter // failed logins per client address; nil disables
	LoginByUser    *ratelimit.Limiter // failed logins per username; nil disables
	Frontend       *spa.Handler       // the built SPA, served for every path outside /api/; nil serves a "not built" page
	Logger         *slog.Logger
	// Now returns the current time, for API token expiry and last use. nil means time.Now.
	Now func() time.Time
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
	pending   *pendingLogins // logins waiting for a two-factor code
	csp       string         // Content-Security-Policy for every response
	setupDone atomic.Bool    // once true, never false again; until then, the database is asked on each request

	expiredUses  tokenClock // when each expired API token's use was last audited
	tokenTouches tokenClock // when each API token's last use was last written
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

var _ gen.StrictServerInterface = (*Server)(nil)

// New builds the server and its routes.
func New(o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Gravity == nil && o.Instances != nil {
		o.Gravity = &gravity.Service{Call: o.Instances.Pool.Do}
	}
	if o.TOTP == nil && o.Store != nil {
		// Never nil with a store: a login must be able to check a code for a user who has two-factor login on.
		o.TOTP = &totp.Service{Store: o.Store, Audit: o.Audit, Cipher: func() *secrets.Cipher {
			if o.Secrets == nil {
				return nil
			}
			return o.Secrets.Cipher()
		}}
	}
	s := &Server{Options: o, mux: http.NewServeMux(), pending: newPendingLogins(), csp: ContentSecurityPolicy}
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
	if o.Frontend != nil {
		s.csp = contentSecurityPolicy(o.Frontend.ScriptHashes())
		s.mux.Handle("/", o.Frontend)
	} else {
		s.mux.Handle("/", spa.NotBuilt())
	}
	return s
}

// Handler returns the server's http.Handler: security headers and the body cap around every route, the API and the
// frontend alike.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", s.csp)
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
	w     http.ResponseWriter
	r     *http.Request
	sess  *auth.Session // nil when there is no valid session, and always for a request made with an API token
	token *tokenCaller  // the API token the request authenticated with, or nil
	user  *caller       // who is making the request, by session or token; nil when neither
	ip    string        // client address, from X-Forwarded-For only behind a trusted proxy

	perms *rbac.Set // resolved on first use; see Server.permissions. Set by the gate for a token

	tokenRefusal *rbac.Error // a refusal the gate found for a token before it could audit it
}

// caller is who is making a request, whether they logged in or used an API token. Handlers for routes that accept a
// token use this rather than sess, which a token request doesn't have.
type caller struct {
	UserID   int64
	Username string
	Source   auth.Method
	RoleIDs  []int64 // a session's roles, or for a token the owner's roles now
	PublicID string  // the session's public ID; empty for a token
	// RolesCheckedAt is when an LDAP user's roles were last confirmed against the directory. Zero for a local user.
	RolesCheckedAt time.Time
}

func sessionCaller(sess *auth.Session) *caller {
	if sess == nil {
		return nil
	}
	c := &caller{UserID: sess.UserID, Username: sess.Username, Source: sess.Source, RoleIDs: sess.RoleIDs, PublicID: sess.PublicID}
	if sess.Source == auth.MethodLDAP {
		c.RolesCheckedAt = sess.RolesCheckedAt
	}
	return c
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
// state-changing requests, authenticates the request by its API token (authenticateToken) when it has an
// Authorization header and by its session (sessionGate) otherwise, and refuses callers that lack the global
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

		access, declared := routePermission[r.Pattern]
		if !declared {
			s.Logger.Error("route has no declared permission", "pattern", r.Pattern)
			writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
			return
		}

		var ri *reqInfo
		if _, bearer := r.Header["Authorization"]; bearer {
			// An API token, in place of a session. CSRF and Origin don't apply: a browser can't send this header to
			// another origin without a CORS preflight, which the app never answers.
			if ri = s.authenticateToken(w, r); ri == nil {
				return
			}
		} else {
			if ri = s.sessionGate(w, r, access); ri == nil {
				return
			}
		}
		ctx := context.WithValue(r.Context(), reqInfoKey{}, ri)
		if ri.token != nil {
			ctx = audit.WithToken(ctx, ri.token.name, ri.token.publicID)
		}
		r = r.WithContext(ctx)
		ri.r = r
		if ri.token != nil && ri.tokenRefusal != nil {
			s.refuse(w, r, ri.tokenRefusal)
			return
		}
		if kind, perm, _ := parseAccess(access); kind == "global" {
			if err := s.requireGlobal(r.Context(), globalPermissions(perm)...); err != nil {
				s.responseError(w, r, err)
				return
			}
		}
		if longRoutes[r.Pattern] {
			// Not every ResponseWriter supports deadlines (a test recorder doesn't); the server's own does.
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(clientreset.RunTimeout + time.Minute))
		}
		next.ServeHTTP(w, r)
	})
}

// sessionGate is the gate for a request without an Authorization header: it loads the session, refuses requests
// without one unless the route is public, checks the Origin and CSRF token on state-changing requests, and holds a
// session whose user must set up two-factor login to the routes for doing that. It answers the request itself and
// returns nil when the request is refused.
func (s *Server) sessionGate(w http.ResponseWriter, r *http.Request, access string) *reqInfo {
	sess, err := s.Sessions.Get(r.Context(), r)
	if err != nil && !errors.Is(err, auth.ErrNoSession) {
		s.Logger.Error("loading session", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
		return nil
	}
	// Before the CSRF check, so a state-changing request whose session has ended (expired, revoked, or a new
	// session key) is told to log in again rather than that its token didn't match. Nothing is changed either way.
	if sess == nil && access != accessPublic {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "You need to log in.")
		return nil
	}
	if !isSafeMethod(r.Method) && (!sameOrigin(r, s.TrustedProxies) || !s.Sessions.CheckCSRF(r, sess)) {
		writeError(w, http.StatusForbidden, "csrf_failed", "The request was refused because its CSRF token or origin didn't match. Reload the page and try again.")
		return nil
	}

	// Held to setting up two-factor login: checked here, for every route that needs a session, so nothing can be
	// reached around it. After the CSRF check, so a forged request learns nothing from the answer.
	if sess != nil && access != accessPublic && !totpSetupRoutes[r.Pattern] {
		hold, err := s.totpSetupRequired(r.Context(), sess.UserID, sess.RoleIDs)
		if err != nil {
			s.Logger.Error("checking the two-factor requirement", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "Something went wrong.")
			return nil
		}
		if hold {
			writeError(w, http.StatusForbidden, "totp_setup_required", msgTOTPSetupRequired)
			return nil
		}
	}
	return &reqInfo{w: w, sess: sess, user: sessionCaller(sess), ip: ratelimit.ClientIP(r, s.TrustedProxies)}
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
// refuse), a failed connection test as a Pi-hole or instance error (see testFailed), an LDAP server that couldn't be
// used as ldap_failed, and a failed Pi-hole call on a target likewise (see piholeFailed); anything else is an unexpected failure, logged in full but reported to the
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
	var de *loginsettings.DirectoryError
	if errors.As(err, &de) {
		body := errorBody("ldap_failed", "The LDAP server couldn't be used, so nothing was saved: "+ldapReason(de.Err))
		details := map[string]any{"detail": de.Err.Error()}
		body.Error.Details = &details
		writeJSON(w, http.StatusBadGateway, body)
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
