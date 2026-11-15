// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"testing"
	"time"
)

// SetRestartPoll makes WaitRestarted ask every poll, and trust FTL once it has kept answering for settle, for the rest
// of the test.
func SetRestartPoll(t *testing.T, poll, settle time.Duration) {
	t.Cleanup(SetRestartTiming(poll, settle))
}
