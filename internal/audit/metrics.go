// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"github.com/Kate-0713/pihole-rbac/internal/metrics"
)

// loggerMetrics counts what Log is given. Log is called once per row, after the row's transaction has committed, so
// the counts are of rows that exist.
type loggerMetrics struct {
	events *metrics.Counter
	logins *metrics.Counter
	known  map[string]bool
}

// SetMetrics makes Log count every entry as pihole_rbac_audit_events_total{action,result}, and every login row as
// pihole_rbac_logins_total{result}. Call it once, before the logger is used; it registers the metrics, which panics
// if they already are. A nil registry counts nothing.
func (l *Logger) SetMetrics(r *metrics.Registry) {
	if r == nil {
		return
	}
	known := map[string]bool{ActionInstanceTest: true}
	for _, a := range actions {
		known[a.Name] = true
	}
	l.m.Store(&loggerMetrics{
		events: r.Counter("pihole_rbac_audit_events_total",
			"Audit rows written, by action and result (success or failure). An action that isn't in the fixed list counts as other.",
			"action", "result"),
		logins: r.Counter("pihole_rbac_logins_total",
			"Finished login attempts from the login audit rows: ok (a session started), failed, or locked_out (the attempt that tripped a login limit). A password that was right but still waiting for a two-factor code isn't finished and isn't counted.",
			"result"),
		known: known,
	})
}

func (m *loggerMetrics) count(e Entry) {
	action := e.Action
	if !m.known[action] {
		action = "other"
	}
	m.events.Inc(action, e.Result())
	if e.Action != ActionLogin {
		return
	}
	switch {
	case e.Err == nil:
		m.logins.Inc("ok")
	case e.Detail["locked_out"] != nil:
		m.logins.Inc("locked_out")
	default:
		m.logins.Inc("failed")
	}
}
