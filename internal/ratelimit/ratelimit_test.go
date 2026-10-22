// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package ratelimit

import (
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(max int, window time.Duration) (*Limiter, *clock) {
	c := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	l := New(max, window)
	l.now = c.now
	return l, c
}

func TestLimiterBlocksAtMaxAndExpires(t *testing.T) {
	l, c := newTest(3, 10*time.Minute)

	for i := 0; i < 2; i++ {
		if l.Fail("a") {
			t.Fatalf("failure %d tripped early", i+1)
		}
		c.t = c.t.Add(time.Minute)
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("blocked before reaching max")
	}
	if !l.Fail("a") {
		t.Fatal("third failure should trip the limit")
	}
	ok, wait := l.Allow("a")
	if ok {
		t.Fatal("should be blocked at max")
	}
	// oldest failure was 2 minutes ago, so 8 minutes remain
	if wait != 8*time.Minute {
		t.Fatalf("retry after = %v, want 8m", wait)
	}
	if l.Fail("a") {
		t.Fatal("failures while blocked must not re-trip")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other keys are unaffected")
	}

	c.t = c.t.Add(8 * time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("still blocked after the oldest failure aged out")
	}
}

func TestBlockedAttemptsDoNotExtendBlock(t *testing.T) {
	l, c := newTest(2, 10*time.Minute)
	l.Fail("a")
	l.Fail("a")
	c.t = c.t.Add(9 * time.Minute)
	l.Fail("a") // attempt while blocked
	c.t = c.t.Add(time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("hammering while blocked extended the block")
	}
}

func TestReset(t *testing.T) {
	l, _ := newTest(2, time.Minute)
	l.Fail("a")
	l.Reset("a")
	l.Fail("a")
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("Reset should forget earlier failures")
	}
}

func TestSweepDropsIdleKeys(t *testing.T) {
	l, c := newTest(5, time.Minute)
	l.Fail("gone")
	c.t = c.t.Add(3 * time.Minute)
	l.Fail("new") // triggers a sweep
	if _, ok := l.fails["gone"]; ok {
		t.Fatal("expired key still held in memory")
	}
}

func TestNilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	if ok, _ := l.Allow("x"); !ok {
		t.Fatal("nil limiter blocked")
	}
	if l.Fail("x") {
		t.Fatal("nil limiter tripped")
	}
	l.Reset("x")
}

func TestClientIP(t *testing.T) {
	// Parsing PIHOLE_RBAC_TRUSTED_PROXIES is tested in internal/config.
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32"), netip.MustParsePrefix("192.168.1.0/24")}
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct, no proxy", "203.0.113.5:4000", nil, "203.0.113.5"},
		{"header ignored from untrusted peer", "203.0.113.5:4000", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted proxy, one hop", "10.0.0.2:5000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client-forged prefix is ignored", "10.0.0.2:5000", []string{"9.9.9.9, 198.51.100.7"}, "198.51.100.7"},
		{"chain of trusted proxies", "10.0.0.2:5000", []string{"198.51.100.7, 192.168.1.9"}, "198.51.100.7"},
		{"split across header lines", "10.0.0.2:5000", []string{"9.9.9.9", "198.51.100.7"}, "198.51.100.7"},
		{"trusted proxy, no header", "10.0.0.2:5000", nil, "10.0.0.2"},
		{"malformed header", "10.0.0.2:5000", []string{"nonsense"}, "10.0.0.2"},
		{"ipv4-mapped ipv6 peer", "[::ffff:10.0.0.2]:5000", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := ClientIP(r, trusted); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}
