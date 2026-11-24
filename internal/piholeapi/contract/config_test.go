// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package contract_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

// Pi-hole's config arrays (dns.hosts, dns.cnameRecords, dhcp.hosts) and the DHCP settings: changed one element, or
// one PATCH, at a time, refused without app_sudo or for an item set by an environment variable, and restarting FTL
// for every item but dns.hosts.

func TestHostRecords(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	host := name(".lan")
	spaced := "192.0.2.20  " + host // two spaces
	stored := "192.0.2.20 " + host
	t.Cleanup(func() { _ = c.DeleteHostRecord(ctx, stored) })

	before, err := c.GetLocalDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !before.AppSudo || before.ReadOnly || before.HostsLocked || before.CNAMEsLocked {
		t.Fatalf("local DNS = %+v, want app_sudo on, not read-only, nothing locked", before)
	}

	t.Run("runs of spaces are collapsed", func(t *testing.T) {
		if err := c.AddHostRecord(ctx, spaced); err != nil {
			t.Fatal(err)
		}
		hosts := readHosts(t, c)
		if !slices.Contains(hosts, stored) || slices.Contains(hosts, spaced) {
			t.Errorf("dns.hosts = %q, want %q stored as %q", hosts, spaced, stored)
		}
	})

	t.Run("a duplicate is refused", func(t *testing.T) {
		if err := c.AddHostRecord(ctx, stored); !errors.Is(err, piholeapi.ErrAlreadyPresent) {
			t.Errorf("err = %v, want ErrAlreadyPresent", err)
		}
	})

	t.Run("a value FTL's validator refuses", func(t *testing.T) {
		err := c.AddHostRecord(ctx, "not-an-address "+host)
		var re *piholeapi.RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a RejectedError", err)
		}
		if slices.Contains(readHosts(t, c), "not-an-address "+host) {
			t.Error("the refused value was saved")
		}
	})

	t.Run("delete matches the whole string exactly", func(t *testing.T) {
		wantStatus(t, c.DeleteHostRecord(ctx, spaced), http.StatusNotFound)
		if err := c.DeleteHostRecord(ctx, stored); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(readHosts(t, c), stored) {
			t.Error("still there after delete")
		}
		wantStatus(t, c.DeleteHostRecord(ctx, stored), http.StatusNotFound)
	})
}

func TestCNAMEs(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	a := name(".lan") + "," + name(".lan")
	b := name(".lan") + "," + name(".lan")
	t.Cleanup(func() {
		_ = c.DeleteCNAME(ctx, a, false)
		_ = c.DeleteCNAME(ctx, b, false)
	})

	t.Run("an add without a restart", func(t *testing.T) {
		if err := c.AddCNAME(ctx, a, false); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(readCNAMEs(t, c), a) {
			t.Errorf("%q not saved", a)
		}
	})

	t.Run("an add that restarts FTL, and the wait for it", func(t *testing.T) {
		since := time.Now()
		if err := c.AddCNAME(ctx, b, true); err != nil {
			t.Fatal(err)
		}
		waitRestarted(t, c, since)
		if !slices.Contains(readCNAMEs(t, c), b) {
			t.Errorf("%q not saved", b)
		}
	})

	t.Run("a value FTL's validator refuses", func(t *testing.T) {
		err := c.AddCNAME(ctx, name(".lan"), false)
		var re *piholeapi.RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a RejectedError", err)
		}
	})

	t.Run("several changes with one restart", func(t *testing.T) {
		errs, restarted, since := c.ApplyCNAMEs(ctx, []piholeapi.CNAMEOp{{Delete: true, Value: a}, {Delete: true, Value: b}})
		if errors.Join(errs...) != nil || !restarted {
			t.Fatalf("errs = %v, restarted = %v, want no errors and a restart", errs, restarted)
		}
		waitRestarted(t, c, since)
		if got := readCNAMEs(t, c); slices.Contains(got, a) || slices.Contains(got, b) {
			t.Errorf("dns.cnameRecords = %q, want both deleted", got)
		}
	})
}

func TestRestartDNS(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	since := time.Now()
	// FTL's API goes down with it, so the request itself can fail with the restart under way.
	if err := c.RestartDNS(context.Background()); err != nil && !errors.Is(err, piholeapi.ErrUnreachable) {
		t.Fatal(err)
	}
	waitRestarted(t, c, since)
}

func TestStaticLeases(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	lease := "02:00:00:00:00:01,192.0.2.50," + name("")
	t.Cleanup(func() { _ = c.DeleteStaticLease(ctx, lease, false) })

	since := time.Now()
	if err := c.AddStaticLease(ctx, lease, true); err != nil {
		t.Fatal(err)
	}
	waitRestarted(t, c, since)
	if !slices.Contains(readDHCP(t, c).Hosts, lease) {
		t.Errorf("%q not saved", lease)
	}
	if err := c.AddStaticLease(ctx, lease, false); !errors.Is(err, piholeapi.ErrAlreadyPresent) {
		t.Errorf("duplicate: err = %v, want ErrAlreadyPresent", err)
	}
	if err := c.DeleteStaticLease(ctx, lease, false); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, c.DeleteStaticLease(ctx, lease, false), http.StatusNotFound)
}

func TestDHCPSettings(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	before := readDHCP(t, c)
	if before.Active {
		t.Fatal("DHCP is on; the tests need a Pi-hole that doesn't serve DHCP")
	}
	t.Cleanup(func() {
		_ = c.PatchDHCP(ctx, piholeapi.DHCPPatch{Start: &before.Start, End: &before.End, Router: &before.Router, Netmask: &before.Netmask}, false)
	})

	t.Run("one PATCH, saved without a restart", func(t *testing.T) {
		start, end, router, mask := "192.0.2.100", "192.0.2.200", "192.0.2.1", "255.255.255.0"
		p := piholeapi.DHCPPatch{Start: &start, End: &end, Router: &router, Netmask: &mask}
		if err := c.PatchDHCP(ctx, p, false); err != nil {
			t.Fatal(err)
		}
		got := readDHCP(t, c)
		if got.Start != start || got.End != end || got.Router != router || got.Netmask != mask || got.Active {
			t.Errorf("read back = %+v, want the new range, still off", got)
		}
	})

	t.Run("a value FTL refuses changes nothing", func(t *testing.T) {
		bad, end := "not-an-address", "192.0.2.201"
		err := c.PatchDHCP(ctx, piholeapi.DHCPPatch{Start: &bad, End: &end}, false)
		var re *piholeapi.RejectedError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a RejectedError", err)
		}
		if got := readDHCP(t, c); got.End == end {
			t.Error("the end of the range changed though the PATCH was refused")
		}
	})

	t.Run("leases read, and can't be deleted with DHCP off", func(t *testing.T) {
		if _, err := c.GetLeases(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteLease(ctx, "192.0.2.150"); !errors.Is(err, piholeapi.ErrDHCPOff) {
			t.Errorf("err = %v, want ErrDHCPOff", err)
		}
	})
}

// An item set through an environment variable can be read, shows as locked, and can't be changed through the API.
func TestConfigLocked(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	d := readDHCP(t, c)
	if !d.Locked[lockedDHCPItem] {
		t.Fatalf("locked = %v, want dhcp.%s locked (set it with FTLCONF_dhcp_%[2]s)", d.Locked, lockedDHCPItem)
	}
	for k := range d.Locked {
		if k != lockedDHCPItem {
			t.Errorf("dhcp.%s is locked too; only dhcp.%s may be", k, lockedDHCPItem)
		}
	}
	lt := "1h"
	if err := c.PatchDHCP(ctx, piholeapi.DHCPPatch{LeaseTime: &lt}, false); !errors.Is(err, piholeapi.ErrConfigLocked) {
		t.Errorf("err = %v, want ErrConfigLocked", err)
	}
	if got := readDHCP(t, c); got.LeaseTime != d.LeaseTime {
		t.Errorf("leaseTime = %q, want it unchanged (%q)", got.LeaseTime, d.LeaseTime)
	}
}

// Without app_sudo, an app-password session can read config but not change it.
func TestAppSudoOff(t *testing.T) {
	tg := newTarget(t)
	tg.setAppSudo(t, false)
	c := tg.client(t)
	ctx := context.Background()

	l, err := c.GetLocalDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l.AppSudo {
		t.Error("local DNS read says app_sudo is on")
	}
	if on, err := c.AppSudo(ctx); err != nil || on {
		t.Errorf("AppSudo = %v, %v; want false", on, err)
	}
	host := "192.0.2.21 " + name(".lan")
	t.Cleanup(func() { _ = c.DeleteHostRecord(ctx, host) })
	if err := c.AddHostRecord(ctx, host); !errors.Is(err, piholeapi.ErrAppSudoOff) {
		t.Errorf("host record: err = %v, want ErrAppSudoOff", err)
	}
	start := "192.0.2.100"
	if err := c.PatchDHCP(ctx, piholeapi.DHCPPatch{Start: &start}, false); !errors.Is(err, piholeapi.ErrAppSudoOff) {
		t.Errorf("DHCP: err = %v, want ErrAppSudoOff", err)
	}
}

// waitRestarted waits for FTL to be back after a restart started at since, then checks it keeps answering: the app
// relies on that, since a real Pi-hole was seen answering once after a restart and then refusing connections again.
func waitRestarted(t *testing.T, c *piholeapi.Client, since time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := c.WaitRestarted(ctx, since, piholeapi.RestartWait); err != nil {
		t.Fatalf("waiting for FTL to restart: %v", err)
	}
	for range 10 {
		if _, err := c.GetStatus(ctx); err != nil {
			t.Fatalf("FTL stopped answering after the wait: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func readHosts(t *testing.T, c *piholeapi.Client) []string {
	t.Helper()
	l, err := c.GetLocalDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l.Hosts
}

func readCNAMEs(t *testing.T, c *piholeapi.Client) []string {
	t.Helper()
	l, err := c.GetLocalDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return l.CNAMEs
}

func readDHCP(t *testing.T, c *piholeapi.Client) *piholeapi.DHCP {
	t.Helper()
	d, err := c.GetDHCP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
