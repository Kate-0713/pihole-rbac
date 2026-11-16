// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Local DNS records live in two of Pi-hole's config arrays, dns.hosts and dns.cnameRecords, which FTL changes one
// element at a time: PUT /api/config/dns/hosts/<value> adds one, DELETE on the same path removes one, matching the
// whole string exactly. The strings are built and checked by internal/localdns; this client only refuses what could
// never be a config value.
//
// An app-password session can only change config while the Pi-hole's webserver.api.app_sudo is on. A dns.cnameRecords
// change restarts FTL after it has answered, unless ?restart=false is sent; a dns.hosts change doesn't, since dnsmasq
// reloads the hosts directory by itself.

// ErrAppSudoOff is Pi-hole refusing a config change because webserver.api.app_sudo is off, so the app's password
// may only read its config.
var ErrAppSudoOff = errors.New("pihole doesn't let the app password change its config (webserver.api.app_sudo is off)")

// ErrConfigLocked is Pi-hole refusing a config change because the item is set by an environment variable, or the
// whole config is read-only (misc.readOnly).
var ErrConfigLocked = errors.New("pihole's config item can't be changed through its API")

// ErrAlreadyPresent is Pi-hole refusing to add a config array element it already has, by its exact string.
var ErrAlreadyPresent = errors.New("pihole already has the config element")

// ErrNotRestarted is WaitRestarted giving up: FTL didn't answer as a restarted process in time.
var ErrNotRestarted = errors.New("pihole didn't come back after restarting")

// API error codes for config changes Pi-hole won't make.
const (
	CodeAppSudoOff     = "pihole_app_sudo_off"
	CodeConfigLocked   = "pihole_config_locked"
	CodeAlreadyPresent = "already_present"
)

// configError is a config change Pi-hole refused for one of the reasons above. It keeps Pi-hole's own error.
type configError struct {
	kind error
	err  error
}

func (e *configError) Error() string        { return e.kind.Error() + ": " + e.err.Error() }
func (e *configError) Unwrap() error        { return e.err }
func (e *configError) Is(target error) bool { return target == e.kind }

// maxConfigValue caps a value sent in a config path, in bytes. FTL's own limit is larger.
const maxConfigValue = 1024

// LocalDNS is a Pi-hole's local DNS config as read: the two arrays exactly as Pi-hole holds them, and what decides
// whether the app can change them.
type LocalDNS struct {
	Hosts  []string
	CNAMEs []string
	// HostsLocked and CNAMEsLocked say the array is set by an environment variable (FTLCONF_dns_hosts, say), which
	// FTL won't let its API change.
	HostsLocked, CNAMEsLocked bool
	// AppSudo is webserver.api.app_sudo: whether an app-password session may change config.
	AppSudo bool
	// ReadOnly is misc.readOnly: the whole config is read-only. Pi-holes without the setting read as false.
	ReadOnly bool
}

// configLeaf is one item of a detailed config read.
type configLeaf[T any] struct {
	Value T `json:"value"`
	Flags struct {
		EnvVar bool `json:"env_var"`
	} `json:"flags"`
}

// GetLocalDNS reads the local DNS records and CNAMEs, and the settings that decide whether the app may change them:
// three reads, all allowed without app_sudo.
func (c *Client) GetLocalDNS(ctx context.Context) (*LocalDNS, error) {
	var dns struct {
		Config struct {
			DNS struct {
				Hosts        *configLeaf[[]string] `json:"hosts"`
				CNAMERecords *configLeaf[[]string] `json:"cnameRecords"`
			} `json:"dns"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/config/dns?detailed=true", nil, &dns); err != nil {
		return nil, err
	}
	d := dns.Config.DNS
	if d.Hosts == nil || d.CNAMERecords == nil {
		return nil, &badResponseError{what: "config read", err: errors.New("dns.hosts or dns.cnameRecords missing")}
	}
	appSudo, err := c.AppSudo(ctx)
	if err != nil {
		return nil, err
	}
	var ro struct {
		Config struct {
			Misc struct {
				ReadOnly bool `json:"readOnly"`
			} `json:"misc"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/config/misc/readOnly", nil, &ro); err != nil {
		return nil, err
	}
	return &LocalDNS{
		Hosts: nonNilStrings(d.Hosts.Value), CNAMEs: nonNilStrings(d.CNAMERecords.Value),
		HostsLocked: d.Hosts.Flags.EnvVar, CNAMEsLocked: d.CNAMERecords.Flags.EnvVar,
		AppSudo: appSudo, ReadOnly: ro.Config.Misc.ReadOnly,
	}, nil
}

// AppSudo reads webserver.api.app_sudo: whether an app-password session, as the app's is, may change config.
func (c *Client) AppSudo(ctx context.Context) (bool, error) {
	var sudo struct {
		Config struct {
			Webserver struct {
				API struct {
					AppSudo bool `json:"app_sudo"`
				} `json:"api"`
			} `json:"webserver"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/config/webserver/api/app_sudo", nil, &sudo); err != nil {
		return false, err
	}
	return sudo.Config.Webserver.API.AppSudo, nil
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// checkConfigValue is the backstop for a value going into a config path: not empty, valid UTF-8, no control
// characters other than a tab (Pi-hole's own host records may hold tabs, and deleting one sends it back), and not
// absurdly long. Values the app adds have passed internal/localdns's far stricter checks.
func checkConfigValue(value string) error {
	switch {
	case value == "", len(value) > maxConfigValue, !utf8.ValidString(value),
		strings.IndexFunc(value, func(r rune) bool { return r != '\t' && unicode.IsControl(r) }) >= 0:
		return fmt.Errorf("%w: config value %q", ErrInvalidArgument, value)
	}
	return nil
}

func configPath(item, value string, restart bool) string {
	return configItemPath("dns", item, value, restart)
}

// configItemPath is the path of one element of a config array: section and item name it (dns and hosts), and value
// is the element, escaped as one path segment.
func configItemPath(section, item, value string, restart bool) string {
	p := "/api/config/" + section + "/" + item + "/" + url.PathEscape(value)
	if !restart {
		p += "?restart=false"
	}
	return p
}

// AddHostRecord adds value to dns.hosts. It doesn't restart FTL.
func (c *Client) AddHostRecord(ctx context.Context, value string) error {
	return c.configWrite(ctx, http.MethodPut, "hosts", value, true)
}

// DeleteHostRecord removes value from dns.hosts, matching it exactly. One Pi-hole doesn't have is a 404 StatusError.
func (c *Client) DeleteHostRecord(ctx context.Context, value string) error {
	return c.configWrite(ctx, http.MethodDelete, "hosts", value, true)
}

// AddCNAME adds value to dns.cnameRecords. With restart, FTL restarts once it has answered, and DNS doesn't answer
// until it is back (see WaitRestarted); without it, the CNAME is saved but only served after the next restart.
func (c *Client) AddCNAME(ctx context.Context, value string, restart bool) error {
	return c.configWrite(ctx, http.MethodPut, "cnameRecords", value, restart)
}

// DeleteCNAME removes value from dns.cnameRecords, matching it exactly, restarting FTL as AddCNAME does. One Pi-hole
// doesn't have is a 404 StatusError.
func (c *Client) DeleteCNAME(ctx context.Context, value string, restart bool) error {
	return c.configWrite(ctx, http.MethodDelete, "cnameRecords", value, restart)
}

func (c *Client) configWrite(ctx context.Context, method, item, value string, restart bool) error {
	return c.configWriteAt(ctx, method, "dns", item, value, restart)
}

// configWriteAt adds or removes one element of the config array section.item.
func (c *Client) configWriteAt(ctx context.Context, method, section, item, value string, restart bool) error {
	if err := checkConfigValue(value); err != nil {
		return err
	}
	return configFailure(c.do(ctx, method, configItemPath(section, item, value, restart), nil, nil))
}

// configReadOnly reads misc.readOnly. Pi-holes without the setting read as false.
func (c *Client) configReadOnly(ctx context.Context) (bool, error) {
	var ro struct {
		Config struct {
			Misc struct {
				ReadOnly bool `json:"readOnly"`
			} `json:"misc"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/config/misc/readOnly", nil, &ro); err != nil {
		return false, err
	}
	return ro.Config.Misc.ReadOnly, nil
}

// configFailure turns Pi-hole's refusals of a config change into ErrAppSudoOff, ErrConfigLocked or
// ErrAlreadyPresent, going by its messages (FTL uses the same keys, forbidden and bad_request, for other refusals):
//   - 403 "…app_sudo is false" when the app password may not change config;
//   - 403 "The config is currently in read-only mode";
//   - 400 "Config items set via environment variables cannot be changed via the API";
//   - 400 "Item already present".
func configFailure(err error) error {
	var se *StatusError
	var re *RejectedError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &se) && se.Code == http.StatusForbidden && strings.Contains(se.Message, "app_sudo"):
		return &configError{kind: ErrAppSudoOff, err: err}
	case errors.As(err, &se) && se.Code == http.StatusForbidden && strings.Contains(se.Message, "read-only mode"):
		return &configError{kind: ErrConfigLocked, err: err}
	case errors.As(err, &re) && strings.Contains(re.Message, "environment variable"):
		return &configError{kind: ErrConfigLocked, err: err}
	case errors.As(err, &re) && strings.HasPrefix(re.Message, "Item already present"):
		return &configError{kind: ErrAlreadyPresent, err: err}
	}
	return err
}

// RestartWait is how long the app waits for FTL to answer again after a change that restarts it.
const RestartWait = 15 * time.Second

// restartPoll is how often WaitRestarted asks, and restartSettle how long a restarted FTL must keep answering
// before it counts as back. Variables so tests can make them shorter.
var (
	restartPoll   = 250 * time.Millisecond
	restartSettle = 2 * time.Second
)

// SetRestartTiming changes how often WaitRestarted asks and how long FTL must keep answering, for tests and the e2e
// server, whose fake Pi-holes restart at once. It returns a function that puts the old values back. Not safe to call
// while a WaitRestarted runs.
func SetRestartTiming(poll, settle time.Duration) (restore func()) {
	oldPoll, oldSettle := restartPoll, restartSettle
	restartPoll, restartSettle = poll, settle
	return func() { restartPoll, restartSettle = oldPoll, oldSettle }
}

// WaitRestarted waits, for up to timeout, until FTL is back after a restart: answering GET /api/info/ftl as a
// process started after since (its uptime is less than the time since since), and still answering as that same
// process restartSettle later. Pass the time just before the write that restarts it.
//
// FTL restarts by exec'ing itself, so its PID doesn't change, but its uptime starts again; and it restarts only after
// answering the write, so the first reads may still reach the old process, which the uptime tells apart. The settle
// time is there because a real Pi-hole (FTL v6.9) was seen answering about a second after a restart and then refusing
// connections again for a moment: an answer is only trusted once FTL has kept answering, its uptime counting on.
//
// It returns nil once FTL is back, ErrNotRestarted when the time is up, or ctx's error.
func (c *Client) WaitRestarted(ctx context.Context, since time.Time, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var firstAt time.Time     // when the restarted process first answered, while it has kept answering since
	var firstUp time.Duration // its uptime then
	for {
		var out struct {
			FTL struct {
				Uptime *float64 `json:"uptime"` // milliseconds
			} `json:"ftl"`
		}
		err := c.do(ctx, http.MethodGet, "/api/info/ftl", nil, &out)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		now := time.Now()
		switch {
		case err != nil || out.FTL.Uptime == nil:
			firstAt = time.Time{} // not answering (again): start over
		default:
			up := time.Duration(*out.FTL.Uptime * float64(time.Millisecond))
			switch {
			case up >= now.Sub(since):
				firstAt = time.Time{} // still the old process
			case firstAt.IsZero() || up < firstUp:
				firstAt, firstUp = now, up // a restarted process, or another restart since the last answer
			case now.Sub(firstAt) >= restartSettle:
				return nil
			}
		}
		if !now.Add(restartPoll).Before(deadline) {
			return ErrNotRestarted
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(restartPoll):
		}
	}
}

// CNAMEOp is one change for ApplyCNAMEs: add Value, or delete it.
type CNAMEOp struct {
	Delete bool
	Value  string
}

// ApplyCNAMEs sends several CNAME changes so that FTL restarts once: every change but the last goes with
// ?restart=false, the last without it. If the last change fails after an earlier one went through, FTL is restarted
// with RestartDNS instead, so the earlier changes are served. It returns each change's error, in order; whether a
// restart was asked for; and the time just before it was, to pass to WaitRestarted.
func (c *Client) ApplyCNAMEs(ctx context.Context, ops []CNAMEOp) (errs []error, restarted bool, since time.Time) {
	errs = make([]error, len(ops))
	anyOK := false
	for i, op := range ops {
		last := i == len(ops)-1
		if last {
			since = time.Now()
		}
		if op.Delete {
			errs[i] = c.DeleteCNAME(ctx, op.Value, last)
		} else {
			errs[i] = c.AddCNAME(ctx, op.Value, last)
		}
		if errs[i] == nil {
			anyOK = true
		}
	}
	switch {
	case len(ops) == 0:
		return errs, false, since
	case errs[len(ops)-1] == nil:
		return errs, true, since
	case anyOK:
		since = time.Now()
		// A failed restart leaves the earlier changes saved, to be served at the next restart; there's nothing more
		// to do about it here.
		_ = c.RestartDNS(ctx)
		return errs, true, since
	}
	return errs, false, since
}
