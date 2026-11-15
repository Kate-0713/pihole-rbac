// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

func TestGetLocalDNS(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	c := newClient(t, ph.URL)

	got, err := c.GetLocalDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hosts == nil || got.CNAMEs == nil || len(got.Hosts)+len(got.CNAMEs) != 0 {
		t.Errorf("empty config read as %#v, want two empty lists", got)
	}
	if got.AppSudo || got.ReadOnly || got.HostsLocked || got.CNAMEsLocked {
		t.Errorf("defaults %+v, want everything off", got)
	}

	hosts := []string{"10.0.0.5 nas.lab", "10.0.0.6\tprinter # office", "fd00::5 nas.lab nas"}
	cnames := []string{"alias.lab,nas.lab", "a.lab,b.lab,nas.lab,300"}
	ph.SetLocalDNS(hosts, cnames)
	ph.SetAppSudo(true)
	ph.SetConfigReadOnly(true)
	ph.LockLocalDNS(true, false)
	got, err = c.GetLocalDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Hosts, hosts) || !slices.Equal(got.CNAMEs, cnames) {
		t.Errorf("read %q and %q, want the strings exactly as Pi-hole holds them", got.Hosts, got.CNAMEs)
	}
	if !got.AppSudo || !got.ReadOnly || !got.HostsLocked || got.CNAMEsLocked {
		t.Errorf("flags %+v", got)
	}
	reqs := ph.Requests()
	for _, want := range []string{"GET /api/config/dns", "GET /api/config/webserver/api/app_sudo", "GET /api/config/misc/readOnly"} {
		if !slices.Contains(reqs, want) {
			t.Errorf("requests %q don't include %q", reqs, want)
		}
	}
}

// TestLocalDNSWrites covers adding and deleting host records and CNAMEs against the fake, which answers as FTL does:
// the value is the rest of the path, matched exactly; a duplicate add is refused; a missing delete is a 404; FTL's
// validator runs; writes need app_sudo; CNAME writes restart FTL unless told not to.
func TestLocalDNSWrites(t *testing.T) {
	ctx := context.Background()
	seedHosts := []string{"10.0.0.5 nas.lab", "10.0.0.6\tprinter"}
	seedCNAMEs := []string{"alias.lab,nas.lab", "odd.lab,nas/lab", "c.lab,nas.lab #why? 100%"}
	tests := []struct {
		name     string
		setup    func(ph *piholetest.Server)
		call     func(c *piholeapi.Client) error
		sent     string // the request, as Requests reports it; "" for none
		code     string // piholeapi.Kind of the error; "" for none
		is       error  // an error the result must match, if any
		hosts    []string
		cnames   []string
		restarts int
	}{
		{
			name: "add a host record", call: func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.7 tv.lab") },
			sent:  "PUT /api/config/dns/hosts/10.0.0.7%20tv.lab",
			hosts: append(slices.Clone(seedHosts), "10.0.0.7 tv.lab"), cnames: seedCNAMEs,
		},
		{
			name: "add an IPv6 host record", call: func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "fd00::7 tv.lab") },
			sent:  "PUT /api/config/dns/hosts/fd00::7%20tv.lab",
			hosts: append(slices.Clone(seedHosts), "fd00::7 tv.lab"), cnames: seedCNAMEs,
		},
		{
			name: "a duplicate is already present", call: func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.5 nas.lab") },
			sent: "PUT /api/config/dns/hosts/10.0.0.5%20nas.lab", code: piholeapi.CodeAlreadyPresent, is: piholeapi.ErrAlreadyPresent,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name: "FTL's validator refuses a bad hostname", call: func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.7 bad..lab") },
			sent: "PUT /api/config/dns/hosts/10.0.0.7%20bad..lab", code: piholeapi.CodeRejected, is: piholeapi.ErrRejected,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name: "delete a host record", call: func(c *piholeapi.Client) error { return c.DeleteHostRecord(ctx, "10.0.0.5 nas.lab") },
			sent: "DELETE /api/config/dns/hosts/10.0.0.5%20nas.lab", hosts: seedHosts[1:], cnames: seedCNAMEs,
		},
		{
			name: "delete Pi-hole's own string with a tab", call: func(c *piholeapi.Client) error { return c.DeleteHostRecord(ctx, "10.0.0.6\tprinter") },
			sent: "DELETE /api/config/dns/hosts/10.0.0.6%09printer", hosts: seedHosts[:1], cnames: seedCNAMEs,
		},
		{
			name: "delete a missing host record", call: func(c *piholeapi.Client) error { return c.DeleteHostRecord(ctx, "10.0.0.5  nas.lab") },
			sent: "DELETE /api/config/dns/hosts/10.0.0.5%20%20nas.lab", code: piholeapi.CodeStatusError,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name: "add a CNAME restarts FTL", call: func(c *piholeapi.Client) error { return c.AddCNAME(ctx, "tv.lab,nas.lab,300", true) },
			sent:  "PUT /api/config/dns/cnameRecords/tv.lab%2Cnas.lab%2C300",
			hosts: seedHosts, cnames: append(slices.Clone(seedCNAMEs), "tv.lab,nas.lab,300"), restarts: 1,
		},
		{
			name: "add a CNAME without a restart", call: func(c *piholeapi.Client) error { return c.AddCNAME(ctx, "tv.lab,nas.lab", false) },
			sent:  "PUT /api/config/dns/cnameRecords/tv.lab%2Cnas.lab",
			hosts: seedHosts, cnames: append(slices.Clone(seedCNAMEs), "tv.lab,nas.lab"),
		},
		{
			name: "delete a CNAME restarts FTL", call: func(c *piholeapi.Client) error { return c.DeleteCNAME(ctx, "alias.lab,nas.lab", true) },
			sent: "DELETE /api/config/dns/cnameRecords/alias.lab%2Cnas.lab", hosts: seedHosts, cnames: seedCNAMEs[1:], restarts: 1,
		},
		{
			name: "delete a CNAME with a slash in it", call: func(c *piholeapi.Client) error { return c.DeleteCNAME(ctx, "odd.lab,nas/lab", false) },
			sent:  "DELETE /api/config/dns/cnameRecords/odd.lab%2Cnas%2Flab",
			hosts: seedHosts, cnames: []string{seedCNAMEs[0], seedCNAMEs[2]},
		},
		{
			name: "delete a CNAME with a comment, ? and %", call: func(c *piholeapi.Client) error { return c.DeleteCNAME(ctx, "c.lab,nas.lab #why? 100%", false) },
			sent:  "DELETE /api/config/dns/cnameRecords/c.lab%2Cnas.lab%20%23why%3F%20100%25",
			hosts: seedHosts, cnames: seedCNAMEs[:2],
		},
		{
			name: "a failed CNAME add doesn't restart", call: func(c *piholeapi.Client) error { return c.AddCNAME(ctx, "alias.lab,nas.lab", true) },
			sent: "PUT /api/config/dns/cnameRecords/alias.lab%2Cnas.lab", code: piholeapi.CodeAlreadyPresent,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name:  "app_sudo off",
			setup: func(ph *piholetest.Server) { ph.SetAppSudo(false) },
			call:  func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.7 tv.lab") },
			sent:  "PUT /api/config/dns/hosts/10.0.0.7%20tv.lab", code: piholeapi.CodeAppSudoOff, is: piholeapi.ErrAppSudoOff,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name:  "app_sudo off for a delete",
			setup: func(ph *piholetest.Server) { ph.SetAppSudo(false) },
			call:  func(c *piholeapi.Client) error { return c.DeleteCNAME(ctx, "alias.lab,nas.lab", true) },
			sent:  "DELETE /api/config/dns/cnameRecords/alias.lab%2Cnas.lab", code: piholeapi.CodeAppSudoOff,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name:  "a read-only config",
			setup: func(ph *piholetest.Server) { ph.SetConfigReadOnly(true) },
			call:  func(c *piholeapi.Client) error { return c.DeleteHostRecord(ctx, "10.0.0.5 nas.lab") },
			sent:  "DELETE /api/config/dns/hosts/10.0.0.5%20nas.lab", code: piholeapi.CodeConfigLocked, is: piholeapi.ErrConfigLocked,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name:  "host records set by an environment variable",
			setup: func(ph *piholetest.Server) { ph.LockLocalDNS(true, false) },
			call:  func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.7 tv.lab") },
			sent:  "PUT /api/config/dns/hosts/10.0.0.7%20tv.lab", code: piholeapi.CodeConfigLocked,
			hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name:  "CNAMEs can still change when only host records are locked",
			setup: func(ph *piholetest.Server) { ph.LockLocalDNS(true, false) },
			call:  func(c *piholeapi.Client) error { return c.AddCNAME(ctx, "tv.lab,nas.lab", false) },
			sent:  "PUT /api/config/dns/cnameRecords/tv.lab%2Cnas.lab",
			hosts: seedHosts, cnames: append(slices.Clone(seedCNAMEs), "tv.lab,nas.lab"),
		},
		{
			name: "a line break is never sent", call: func(c *piholeapi.Client) error { return c.AddHostRecord(ctx, "10.0.0.7 tv.lab\n10.0.0.8 evil") },
			is: piholeapi.ErrInvalidArgument, hosts: seedHosts, cnames: seedCNAMEs,
		},
		{
			name: "an empty value is never sent", call: func(c *piholeapi.Client) error { return c.DeleteCNAME(ctx, "", true) },
			is: piholeapi.ErrInvalidArgument, hosts: seedHosts, cnames: seedCNAMEs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			ph.SetLocalDNS(seedHosts, seedCNAMEs)
			ph.SetAppSudo(true)
			ph.SetRestartOutage(0)
			if tt.setup != nil {
				tt.setup(ph)
			}
			c := newClient(t, ph.URL)
			err := tt.call(c)
			if got := piholeapi.Kind(err); got != tt.code {
				t.Errorf("error %v has code %q, want %q", err, got, tt.code)
			}
			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("error %v doesn't match %v", err, tt.is)
			}
			if tt.code == "" && tt.is == nil && err != nil {
				t.Errorf("unexpected error %v", err)
			}
			if tt.code == piholeapi.CodeStatusError {
				var se *piholeapi.StatusError
				if !errors.As(err, &se) || se.Code != http.StatusNotFound {
					t.Errorf("error %v isn't a 404", err)
				}
			}
			var writes []string
			for _, r := range ph.Requests() {
				if !slices.Contains([]string{"GET"}, r[:3]) {
					writes = append(writes, r)
				}
			}
			switch {
			case tt.sent == "" && len(writes) != 0:
				t.Errorf("sent %q, want nothing", writes)
			case tt.sent != "" && !slices.Equal(writes, []string{tt.sent}):
				t.Errorf("sent %q, want %q", writes, tt.sent)
			}
			hosts, cnames := ph.LocalDNS()
			if !slices.Equal(hosts, tt.hosts) || !slices.Equal(cnames, tt.cnames) {
				t.Errorf("config is %q and %q, want %q and %q", hosts, cnames, tt.hosts, tt.cnames)
			}
			if got := ph.Restarts(); got != tt.restarts {
				t.Errorf("%d restarts, want %d", got, tt.restarts)
			}
		})
	}
}

func TestWaitRestarted(t *testing.T) {
	piholeapi.SetRestartPoll(t, 10*time.Millisecond, 50*time.Millisecond)
	ctx := context.Background()

	t.Run("after a restart", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.SetAppSudo(true)
		ph.SetRestartOutage(3)
		c := newClient(t, ph.URL)
		since := time.Now()
		if err := c.AddCNAME(ctx, "a.lab,b.lab", true); err != nil {
			t.Fatal(err)
		}
		if err := c.WaitRestarted(ctx, since, 5*time.Second); err != nil {
			t.Fatalf("WaitRestarted: %v", err)
		}
		if ph.Restarts() != 1 {
			t.Errorf("%d restarts", ph.Restarts())
		}
		if _, err := c.GetLocalDNS(ctx); err != nil {
			t.Errorf("Pi-hole isn't answering after WaitRestarted: %v", err)
		}
	})
	t.Run("answering briefly and going away again isn't back yet", func(t *testing.T) {
		// As a real Pi-hole (FTL v6.9) did: a restarted process answers, then refuses connections for a moment.
		ph := piholetest.New(t, password)
		ph.SetAppSudo(true)
		ph.SetRestartPattern(2, 1, 4)
		c := newClient(t, ph.URL)
		since := time.Now()
		if err := c.AddCNAME(ctx, "a.lab,b.lab", true); err != nil {
			t.Fatal(err)
		}
		if err := c.WaitRestarted(ctx, since, 5*time.Second); err != nil {
			t.Fatalf("WaitRestarted: %v", err)
		}
		for i := range 5 {
			if _, err := c.GetLocalDNS(ctx); err != nil {
				t.Fatalf("read %d after WaitRestarted failed, so it returned before Pi-hole was back: %v", i, err)
			}
		}
	})
	t.Run("a settle time with nothing going wrong", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.SetAppSudo(true)
		ph.SetRestartOutage(0)
		c := newClient(t, ph.URL)
		since := time.Now()
		if err := c.AddCNAME(ctx, "a.lab,b.lab", true); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := c.WaitRestarted(ctx, since, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d < 50*time.Millisecond {
			t.Errorf("returned after %s, before the settle time", d)
		}
	})
	t.Run("the old process still answering isn't a restart", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.SetAppSudo(true)
		c := newClient(t, ph.URL)
		since := time.Now()
		if err := c.AddHostRecord(ctx, "10.0.0.5 a.lab"); err != nil { // host records don't restart FTL
			t.Fatal(err)
		}
		start := time.Now()
		if err := c.WaitRestarted(ctx, since, 100*time.Millisecond); !errors.Is(err, piholeapi.ErrNotRestarted) {
			t.Fatalf("WaitRestarted = %v, want ErrNotRestarted", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("took %s for a 100ms timeout", d)
		}
	})
	t.Run("down for longer than the timeout", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.SetAppSudo(true)
		ph.SetRestartOutage(1000)
		c := newClient(t, ph.URL)
		since := time.Now()
		if err := c.AddCNAME(ctx, "a.lab,b.lab", true); err != nil {
			t.Fatal(err)
		}
		if err := c.WaitRestarted(ctx, since, 100*time.Millisecond); !errors.Is(err, piholeapi.ErrNotRestarted) {
			t.Fatalf("WaitRestarted = %v, want ErrNotRestarted", err)
		}
	})
	t.Run("a cancelled context", func(t *testing.T) {
		ph := piholetest.New(t, password)
		c := newClient(t, ph.URL)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := c.WaitRestarted(cctx, time.Now(), time.Second); !errors.Is(err, context.Canceled) {
			t.Fatalf("WaitRestarted = %v, want context.Canceled", err)
		}
	})
}
