// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package logging sets up where the app's logs go: always stdout (journald under systemd, `docker logs` in Docker),
// and, when a log directory is configured, also one file per calendar day in that directory, with files older than
// the retention deleted. Standard library only: the need is one file per day and age-based pruning, which doesn't
// justify a rotation library.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// FilePrefix and FileExt make the daily file names: pihole-rbac-2026-10-26.log.
	FilePrefix = "pihole-rbac-"
	FileExt    = ".log"

	dateFormat = "2006-01-02"
	dirMode    = 0o750
	// The log holds usernames, client addresses and, while first-run setup is open, the setup token, so it isn't
	// world-readable.
	fileMode = 0o640
)

// Options says where logs go.
type Options struct {
	// Dir is the directory for the daily files. Empty means stdout only.
	Dir string
	// RetentionDays is how many days of files to keep; 0 keeps them forever.
	RetentionDays int
	Level         slog.Level

	Stdout io.Writer        // default os.Stdout
	Stderr io.Writer        // where problems with the file are reported; default os.Stderr
	Now    func() time.Time // default time.Now; the file date is in local time, as in v1
}

// Logs is the app's log output.
type Logs struct {
	// Writer is stdout plus the current day's file, for writers outside slog such as the AUDIT lines.
	Writer io.Writer
	Logger *slog.Logger
	file   *dailyFile
}

// Open sets up the log output. With a directory, it creates the directory if needed and opens today's file, so a
// directory the app can't write to stops startup with a clear error rather than losing the logs silently.
func Open(opts Options) (*Logs, error) {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Logs{Writer: opts.Stdout}
	if opts.Dir != "" {
		f, err := openDaily(opts)
		if err != nil {
			return nil, err
		}
		l.file = f
		// stdout first: if the file can't be written, the line still reaches the journal.
		l.Writer = io.MultiWriter(opts.Stdout, f)
	}
	l.Logger = slog.New(slog.NewTextHandler(l.Writer, &slog.HandlerOptions{Level: opts.Level}))
	return l, nil
}

// Close closes the current file. Lines written afterwards go to stdout only.
func (l *Logs) Close() error {
	if l.file == nil {
		return nil
	}
	return l.file.close()
}

// dailyFile writes to <dir>/pihole-rbac-YYYY-MM-DD.log, moving to a new file when the date changes (checked on each
// write, so no background goroutine is needed) and deleting old files each time it does.
type dailyFile struct {
	dir           string
	retentionDays int
	now           func() time.Time
	stderr        io.Writer

	mu       sync.Mutex
	file     *os.File
	date     string // the date of file
	reported string // the date a failure was last reported, so a broken disk doesn't repeat it on every line
	closed   bool
}

func openDaily(opts Options) (*dailyFile, error) {
	if err := os.MkdirAll(opts.Dir, dirMode); err != nil {
		return nil, fmt.Errorf("log directory: %w", err)
	}
	d := &dailyFile{dir: opts.Dir, retentionDays: opts.RetentionDays, now: opts.Now, stderr: opts.Stderr}
	if err := d.rotate(d.now().Format(dateFormat)); err != nil {
		return nil, err
	}
	return d, nil
}

// Name returns the path of the file for date (YYYY-MM-DD).
func Name(dir, date string) string {
	return filepath.Join(dir, FilePrefix+date+FileExt)
}

// rotate opens the file for date and prunes old files. On failure the previous file, if any, stays open. Callers hold
// d.mu, except openDaily, before d is shared.
func (d *dailyFile) rotate(date string) error {
	// Append: a restart part-way through a day continues that day's file.
	f, err := os.OpenFile(Name(d.dir, date), os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("log file: %w", err)
	}
	if d.file != nil {
		_ = d.file.Close()
	}
	d.file, d.date = f, date
	d.prune(date)
	return nil
}

// prune deletes this app's dated files older than the retention. Anything else in the directory is left alone.
func (d *dailyFile) prune(today string) {
	if d.retentionDays <= 0 {
		return
	}
	t, err := time.Parse(dateFormat, today)
	if err != nil {
		return
	}
	cutoff := t.AddDate(0, 0, -d.retentionDays)
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		d.report(today, fmt.Errorf("pruning old log files: %w", err))
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(name, FilePrefix) || !strings.HasSuffix(name, FileExt) {
			continue
		}
		date, err := time.Parse(dateFormat, strings.TrimSuffix(strings.TrimPrefix(name, FilePrefix), FileExt))
		if err != nil {
			continue // not one of ours
		}
		if date.Before(cutoff) {
			if err := os.Remove(filepath.Join(d.dir, name)); err != nil {
				d.report(today, fmt.Errorf("pruning old log files: %w", err))
			}
		}
	}
}

// Write never fails: a log file that can't be written mustn't stop the line reaching stdout (io.MultiWriter stops at
// the first error) or fail the request that logged it. Problems are reported on stderr once a day.
func (d *dailyFile) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return len(p), nil
	}
	today := d.now().Format(dateFormat)
	if today != d.date {
		if err := d.rotate(today); err != nil {
			// Keep writing to the previous day's file rather than dropping lines.
			d.report(today, err)
		}
	}
	if _, err := d.file.Write(p); err != nil {
		d.report(today, err)
	}
	return len(p), nil
}

func (d *dailyFile) report(today string, err error) {
	if d.reported == today {
		return
	}
	d.reported = today
	fmt.Fprintf(d.stderr, "logging: %v\n", err)
}

func (d *dailyFile) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.file.Close()
}
