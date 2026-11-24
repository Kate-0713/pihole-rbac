// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package contract_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
)

func TestAuth(t *testing.T) {
	tg := newTarget(t)
	ctx := context.Background()

	t.Run("the app password logs in", func(t *testing.T) {
		if _, err := tg.client(t).GetStatus(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a wrong password is refused", func(t *testing.T) {
		_, err := tg.clientWith(t, "contract-wrong-password").GetStatus(ctx)
		if !errors.Is(err, piholeapi.ErrAuthRejected) {
			t.Errorf("err = %v, want ErrAuthRejected", err)
		}
	})

	t.Run("closing logs out", func(t *testing.T) {
		c := tg.client(t)
		if _, err := c.GetStatus(ctx); err != nil {
			t.Fatal(err)
		}
		if err := c.Close(ctx); err != nil {
			t.Errorf("logging out: %v", err)
		}
	})
}

func TestBlocking(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = c.SetBlocking(ctx, true, 0) })

	t.Run("off with a timer", func(t *testing.T) {
		st, err := c.SetBlocking(ctx, false, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if st.Blocking != piholeapi.BlockingDisabled || st.Timer == nil || *st.Timer <= 0 || *st.Timer > 60 {
			t.Errorf("status = %+v, want disabled with up to 60 seconds left", st)
		}
		read, err := c.GetStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if read.Blocking != piholeapi.BlockingDisabled || read.Timer == nil {
			t.Errorf("read back = %+v, want disabled with a timer", read)
		}
	})

	t.Run("on again, which drops the timer", func(t *testing.T) {
		st, err := c.SetBlocking(ctx, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		if st.Blocking != piholeapi.BlockingEnabled || st.Timer != nil {
			t.Errorf("status = %+v, want enabled with no timer", st)
		}
	})

	t.Run("off with no timer", func(t *testing.T) {
		st, err := c.SetBlocking(ctx, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		if st.Blocking != piholeapi.BlockingDisabled || st.Timer != nil {
			t.Errorf("status = %+v, want disabled with no timer", st)
		}
	})
}

// The summaries only have to decode: their numbers depend on what the Pi-hole has answered.
func TestSummaries(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()
	if _, err := c.GetLiveSummary(ctx); err != nil {
		t.Errorf("live summary: %v", err)
	}
	if _, err := c.GetDatabaseSummary(ctx, time.Now().Add(-time.Hour), time.Now()); err != nil {
		t.Errorf("database summary: %v", err)
	}
}

// A gravity run downloads one small list the test serves itself, so it needs no internet access. The Pi-hole must be
// able to reach the test's address, 127.0.0.1: CI runs Pi-hole's container on the host's network for this.
func TestGravity(t *testing.T) {
	tg := newTarget(t)
	c := tg.client(t)
	ctx := context.Background()

	domains := []string{name(".example"), name(".example"), name(".example")}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, "# "+prefix+"list")
		for _, d := range domains {
			_, _ = fmt.Fprintln(w, d)
		}
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	addr := "http://" + ln.Addr().String() + "/" + name(".txt")
	if _, err := c.AddList(ctx, piholeapi.ListEntry{Address: addr, Type: "block", Enabled: true, Groups: []int{0}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.DeleteList(ctx, addr, "block") })

	before, err := c.GetLiveSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	if err := c.RunGravity(ctx, func(l string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, l)
	}); err != nil {
		t.Fatalf("gravity: %v\n%s", err, strings.Join(lines, "\n"))
	}
	if len(lines) == 0 {
		t.Error("no output")
	}
	// gravity swaps in a new database file, and FTL only notices within a second or so, then reloads; until then the
	// summary and the lists are read from the old one. last_update changing is the sign it has loaded the new one.
	sum := waitGravityLoaded(t, c, before.Gravity.LastUpdate)
	if sum.Gravity.DomainsBeingBlocked <= 0 {
		t.Errorf("gravity summary = %+v, want domains", sum.Gravity)
	}

	l := findList(t, c, addr, "block")
	if l == nil || l.Status != piholeapi.ListStatusUpdated || l.Number <= 0 || l.DateUpdated <= 0 {
		t.Errorf("list after gravity = %+v, want downloaded (status %d) with domains", l, piholeapi.ListStatusUpdated)
	}
	if tg.real() && l != nil && l.Number != len(domains) {
		t.Errorf("list has %d domains, want %d", l.Number, len(domains))
	}
}

// waitGravityLoaded waits until the summary's gravity last_update is no longer previous, and returns that summary.
func waitGravityLoaded(t *testing.T, c *piholeapi.Client, previous int64) *piholeapi.LiveSummary {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; {
		sum, err := c.GetLiveSummary(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if sum.Gravity.LastUpdate != previous && sum.Gravity.LastUpdate > 0 {
			return sum
		}
		if time.Now().After(deadline) {
			t.Fatalf("gravity's last_update still %d: FTL didn't load the new gravity database", previous)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
