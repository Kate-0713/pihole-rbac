// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"errors"
	"github.com/Kate-0713/pihole-rbac/internal/metrics/metricstest"
	"io"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/metrics"
)

func TestLoggerMetrics(t *testing.T) {
	reg := metrics.New()
	l := NewLogger(io.Discard)
	l.SetMetrics(reg)

	l.Log(Entry{Username: "a", Action: ActionLogin, Detail: map[string]any{"method": "local"}})
	l.Log(Entry{Username: "a", Action: ActionLogin, Err: errors.New("invalid credentials")})
	l.Log(Entry{Username: "a", Action: ActionLogin, Err: errors.New("invalid credentials"), Detail: map[string]any{"locked_out": "address"}})
	l.Log(Entry{Username: "a", Action: ActionLogout})
	l.Log(Entry{Username: "a", Action: ActionLogout})
	l.Log(Entry{Username: "a", Action: ActionInstanceTest, Err: errors.New("denied")})
	// Whatever a typo or a future action is called, it can't make a series.
	l.Log(Entry{Username: "a", Action: "made-up-" + strings.Repeat("x", 10)})

	var b strings.Builder
	if _, err := reg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`pihole_rbac_logins_total{result="ok"} 1`,
		`pihole_rbac_logins_total{result="failed"} 1`,
		`pihole_rbac_logins_total{result="locked_out"} 1`,
		`pihole_rbac_audit_events_total{action="login",result="success"} 1`,
		`pihole_rbac_audit_events_total{action="login",result="failure"} 2`,
		`pihole_rbac_audit_events_total{action="logout",result="success"} 2`,
		`pihole_rbac_audit_events_total{action="instance_test",result="failure"} 1`,
		`pihole_rbac_audit_events_total{action="other",result="success"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "made-up") || strings.Contains(out, `"a"`) {
		t.Errorf("an action or a username became a label:\n%s", out)
	}
	metricstest.Dump(t, reg)
}

func TestLoggerWithoutMetrics(t *testing.T) {
	l := NewLogger(io.Discard)
	l.SetMetrics(nil)
	l.Log(Entry{Username: "a", Action: ActionLogin})
}
