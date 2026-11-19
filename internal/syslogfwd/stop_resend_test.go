// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"context"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/syslogfwd/syslogtest"
)

// cancelOnSet cancels the forwarder's context as SetCursor starts and fails as a database does for a cancelled
// context: the stop() of a delete landing between the network write and the cursor save.
type cancelOnSet struct {
	*memStore
	cancel context.CancelFunc
}

func (c cancelOnSet) SetCursor(ctx context.Context, d, last int64, at time.Time) error {
	c.cancel()
	return ctx.Err()
}

// fixedAt is what service.go's fixedCursor does for the drain after a delete.
type fixedAt struct {
	*memStore
	last int64
}

func (f fixedAt) Cursor(context.Context, int64) (int64, error)             { return f.last, nil }
func (f fixedAt) SetCursor(context.Context, int64, int64, time.Time) error { return nil }

func TestForwarderStoppedMidSaveDoesNotResendOnDrain(t *testing.T) {
	c := syslogtest.NewTCP(t)
	st := newMem(3)
	st.cursors[1] = 2 // rows 1-2 sent; row 3 is the logdest_delete entry

	ctx, cancel := context.WithCancel(context.Background())
	f := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: cancelOnSet{st, cancel}})
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	<-done // stop() returns once Run has

	// Delete: the drain starts from the last position the stopped forwarder knew.
	last := f.Status().LastID
	g := fast(&Forwarder{Dest: dest(c, TransportTCP), Store: fixedAt{st, last}})
	defer g.Close()
	if err := g.Drain(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(c.Messages()); n != 1 {
		t.Errorf("row 3 reached the collector %d times, want 1 (live forwarder's last known cursor: %d)", n, last)
	}
}
