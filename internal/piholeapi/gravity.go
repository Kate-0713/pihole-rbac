// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultGravityTimeout bounds one gravity run, from the request to the end of its output. A run downloads every
// list, which takes from seconds to a few minutes.
const DefaultGravityTimeout = 15 * time.Minute

// ErrGravityRunning is Pi-hole refusing a gravity run because one is already going (409 gravity_running).
var ErrGravityRunning = errors.New("pihole is already running gravity")

// ErrGravityFailed is a gravity run that Pi-hole reported as failed, or whose output stopped before the end.
var ErrGravityFailed = errors.New("gravity failed")

const (
	// maxGravityLine caps one line of output passed on. The rest of a longer line is dropped.
	maxGravityLine = 64 << 10
	// maxGravityOutput caps how much output is passed on. Past it the output is still read, so the run's outcome
	// is known, but no more lines are passed on.
	maxGravityOutput = 16 << 20
	// gravityFailedLine is the line FTL adds to the end of the output when the run failed. FTL has already answered
	// 200 by then, so this is the only sign of a failure apart from the output being cut short.
	gravityFailedLine = "Gravity failed"
)

// RunGravity runs gravity on Pi-hole and passes each line of its output to line, as it arrives, cleaned for display
// (see CleanGravityLine).
//
// It returns nil when the output ended normally, ErrGravityRunning when Pi-hole is already running gravity, and an
// error wrapping ErrGravityFailed when Pi-hole reported a failure or the output stopped before the end. Pi-hole
// carries on with a run whose client has gone away, so a cancelled ctx returns ctx's error but doesn't stop the run.
func (c *Client) RunGravity(ctx context.Context, line func(string)) error {
	for attempt := 0; ; attempt++ {
		sid, err := c.session(ctx)
		if err != nil {
			return err
		}
		code, err := c.runGravity(ctx, sid, line)
		// A 401 means Pi-hole refused the request before starting anything, so trying again is safe.
		if code == http.StatusUnauthorized && attempt == 0 {
			c.forget(sid)
			continue
		}
		return err
	}
}

func (c *Client) runGravity(ctx context.Context, sid string, line func(string)) (int, error) {
	const path = "/api/action/gravity"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("X-FTL-SID", sid)

	resp, err := c.gravity.Do(req)
	if err != nil {
		return 0, c.transportError(ctx, "calling", err)
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusConflict {
		return resp.StatusCode, ErrGravityRunning
	}
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, statusError(resp, http.MethodPost, path)
	}
	last, err := readGravityOutput(resp.Body, line)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return resp.StatusCode, ctxErr
		}
		return resp.StatusCode, fmt.Errorf("%w: the output stopped before the end: %v", ErrGravityFailed, err)
	}
	if last == gravityFailedLine {
		return resp.StatusCode, fmt.Errorf("%w: Pi-hole reported that the run failed", ErrGravityFailed)
	}
	return resp.StatusCode, nil
}

// readGravityOutput passes each line of r to line, cleaned with CleanGravityLine, and returns the last non-empty one.
// An error is anything but a clean end of the output.
func readGravityOutput(r io.Reader, line func(string)) (string, error) {
	br := bufio.NewReaderSize(r, 4096)
	var (
		buf    []byte
		long   bool // the current line passed maxGravityLine
		passed int
		last   string
	)
	emit := func() {
		s := CleanGravityLine(string(buf))
		if shown := strings.TrimSpace(s); shown != "" {
			last = shown
		}
		if passed < maxGravityOutput {
			passed += len(s)
			line(s)
		}
		buf, long = buf[:0], false
	}
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			end := len(chunk)
			complete := chunk[end-1] == '\n'
			if complete {
				end--
			}
			if room := maxGravityLine - len(buf); !long && room > 0 {
				buf = append(buf, chunk[:min(end, room)]...)
			}
			if len(buf) >= maxGravityLine {
				long = true
			}
			if complete {
				emit()
			}
		}
		switch {
		case err == nil, errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(buf) > 0 {
				emit()
			}
			return last, nil
		default:
			if len(buf) > 0 {
				emit()
			}
			return last, err
		}
	}
}

// CleanGravityLine turns one line of gravity's output into the text a terminal would show, safe to display as text:
// gravity redraws progress lines with a carriage return and an erase code, so only the last non-empty part after a
// carriage return is kept; terminal escape sequences and other control characters are removed (a tab becomes a
// space); invalid UTF-8 is replaced; and trailing spaces are trimmed.
func CleanGravityLine(s string) string {
	parts := strings.Split(s, "\r")
	for i := len(parts) - 1; i >= 0; i-- {
		if c := cleanTerminal(parts[i]); strings.TrimSpace(c) != "" || i == 0 {
			return c
		}
	}
	return ""
}

// cleanTerminal removes escape sequences and control characters from s.
func cleanTerminal(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x1b:
			// CSI: ESC [ parameters (0x30-0x3f) intermediates (0x20-0x2f) final (0x40-0x7e). Any other escape is
			// ESC and one more character.
			if i+1 < len(s) && s[i+1] == '[' {
				j := i + 2
				for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
					j++
				}
				if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
					j++
				}
				i = j - 1
			} else if i+1 < len(s) {
				i++
			}
		case c == '\t':
			b.WriteByte(' ')
		case c < 0x20 || c == 0x7f:
			// dropped
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimRight(b.String(), " ")
}
