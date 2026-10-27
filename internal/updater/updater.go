// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package updater carries out an update request on an LXC install. It runs as root, started by
// pihole-rbac-update.service when the app touches the request file, and is the already-installed binary, so the code
// doing the update is the trusted one. It takes nothing from the app but the request row: it works out the release
// itself from the fixed repository, verifies it with the built-in key, refuses anything not newer than the running
// version, backs up the database, swaps the binary, restarts the service and waits for it to become healthy, and puts
// the previous binary and database back if it doesn't.
package updater

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/release"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Service is the app's systemd unit.
const Service = "pihole-rbac.service"

// Source is where releases come from. *release.Client is the only one outside tests.
type Source interface {
	Latest(ctx context.Context) (release.Release, error)
	Checksums(ctx context.Context, v release.Version) (release.Checksums, error)
	Archive(ctx context.Context, v release.Version, arch string, sums release.Checksums) ([]byte, error)
}

// System is what the updater does to the host besides files: systemd, the health check, running the new binary, and
// giving files to the service user.
type System interface {
	Systemctl(ctx context.Context, args ...string) error
	Health(ctx context.Context) error
	// BinaryVersion runs `<path> version` and returns its output.
	BinaryVersion(ctx context.Context, path string) (string, error)
	// Chown gives name, inside dir, to the service user and group. It never follows a symlink: the data directory
	// belongs to the service user, so anything in it may have been replaced by a compromised app.
	Chown(dir *os.Root, name string) error
}

// Updater carries out one request. The zero values of the optional fields are the defaults.
type Updater struct {
	DataDir     string // /var/lib/pihole-rbac
	Binary      string // /usr/local/bin/pihole-rbac
	RequestFile string // removed first, so pihole-rbac-update.path doesn't start the service again
	Arch        string // runtime.GOARCH
	Source      Source
	System      System
	Current     func() (release.Version, bool) // nil means release.Current
	Now         func() time.Time               // nil means time.Now
	Out         io.Writer                      // progress lines, for the journal; nil means os.Stdout

	HealthWait  time.Duration // how long the new version gets to become healthy; default 60 seconds
	HealthPoll  time.Duration // default 1 second
	Stable      time.Duration // healthy again this long after the first success; default 5 seconds
	KeepBackups int           // the updater's own database backups to keep; default 5
}

// Outcome statuses, as in update_requests.
const (
	StatusDone       = "done"
	StatusFailed     = "failed"
	StatusRolledBack = "rolled_back"
)

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) out() io.Writer {
	if u.Out != nil {
		return u.Out
	}
	return os.Stdout
}

func (u *Updater) dbPath() string { return filepath.Join(u.DataDir, store.FileName) }

// The updater runs as root, but the data directory and everything in it belong to the service user, so a compromised
// app could have replaced any entry in it with a symlink: backups pointing at /usr/local/bin, say, which a chown would
// then hand to the app, and with it the binary root runs. So every file operation in the data directory goes through
// an os.Root opened on it, which refuses to resolve a path outside it, and ownership changes never follow a symlink.
// The directory itself can't be swapped, since its parent is root's.

// backupsName is the backups directory's name inside the data directory.
func (u *Updater) backupsName() string { return filepath.Base(store.BackupDir(u.DataDir)) }

// regularFile reports an error unless name, inside dir, is a regular file rather than a symlink or anything else.
func regularFile(dir *os.Root, name string) error {
	fi, err := dir.Lstat(name)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file (%s): refusing to use it", name, fi.Mode().Type())
	}
	return nil
}

// Run takes the oldest pending request and carries it out. It returns the request's outcome, or "" when there was
// no pending request. An error means the request couldn't be read or recorded at all; an update that fails is an
// outcome, not an error.
func (u *Updater) Run(ctx context.Context) (string, error) {
	if u.RequestFile != "" {
		if err := os.Remove(u.RequestFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(u.out(), "removing %s: %v\n", u.RequestFile, err)
		}
	}
	root, err := os.OpenRoot(u.DataDir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	j := &job{u: u, root: root}
	if err := j.open(ctx); err != nil {
		return "", err
	}
	defer j.close()

	req, err := j.q.ClaimUpdateRequest(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		fmt.Fprintln(u.out(), "No pending update request.")
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("claiming the update request: %w", err)
	}
	j.id = req.ID
	j.logf("Update request %d from %s taken by the updater.", req.ID, req.RequestedByName)

	status := j.update(ctx, req)
	// A finished request is recorded even if ctx has ended (the unit's timeout, say).
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	n, err := j.q.FinishUpdateRequest(fctx, db.FinishUpdateRequestParams{
		Status: status, FinishedAt: sql.NullInt64{Int64: store.Millis(u.now()), Valid: true}, ID: req.ID,
	})
	if err != nil {
		return status, fmt.Errorf("recording the outcome of update request %d: %w", req.ID, err)
	}
	if n == 0 {
		j.logf("The app had already marked this request failed (it took too long); leaving it so.")
	}
	return status, nil
}

// job is one request being carried out.
type job struct {
	u    *Updater
	root *os.Root // the data directory; see backupsName
	d    *sql.DB
	q    *db.Queries
	id   int64
	// lines is every log line written, so lines lost when the database is restored from a backup can be written again.
	lines []string
}

func (j *job) open(ctx context.Context) error {
	// SQLite opens the database by path, so check first that it is the file itself and not a symlink to one root can
	// write elsewhere.
	if err := regularFile(j.root, store.FileName); err != nil {
		return fmt.Errorf("opening the database: %w", err)
	}
	d, err := store.OpenUnmigrated(ctx, j.u.DataDir)
	if err != nil {
		return err
	}
	j.d, j.q = d, db.New(d)
	return nil
}

func (j *job) close() {
	if j.d != nil {
		j.d.Close()
		j.d, j.q = nil, nil
	}
}

// logf writes a progress line to the request's log and to the journal. A line that can't be stored is still printed.
func (j *job) logf(format string, args ...any) {
	line := j.u.now().UTC().Format("15:04:05") + " " + fmt.Sprintf(format, args...) + "\n"
	j.lines = append(j.lines, line)
	fmt.Fprint(j.u.out(), line)
	if j.q == nil || j.id == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := j.q.AppendUpdateLog(ctx, db.AppendUpdateLogParams{Line: line, ID: j.id}); err != nil {
		fmt.Fprintf(j.u.out(), "writing the log line to the database: %v\n", err)
	}
}

func (j *job) failf(format string, args ...any) string {
	j.logf(format, args...)
	return StatusFailed
}

func (j *job) update(ctx context.Context, req db.UpdateRequest) string {
	u := j.u
	current := u.Current
	if current == nil {
		current = release.Current
	}
	cur, ok := current()
	if !ok {
		return j.failf("This is a development build, which can't be compared with releases: refusing to update it. Install a release with install.sh.")
	}
	if !release.SupportedArch(u.Arch) {
		return j.failf("Releases aren't built for %s.", u.Arch)
	}

	var target release.Version
	if req.TargetVersion.Valid {
		v, err := release.ParseTag(req.TargetVersion.String)
		if err != nil {
			return j.failf("The requested version %q isn't a release tag.", req.TargetVersion.String)
		}
		target = v
		if target.Compare(cur) <= 0 {
			return j.failf("%s isn't newer than the running %s: downgrades are refused.", target.Tag(), cur.Tag())
		}
	} else {
		j.logf("Looking up the latest release of %s.", release.Repository)
		rel, err := u.Source.Latest(ctx)
		if errors.Is(err, release.ErrNoRelease) {
			return j.failf("No release has been published yet.")
		}
		if err != nil {
			return j.failf("Couldn't find the latest release: %v", err)
		}
		target = rel.Version
		if target.Compare(cur) <= 0 {
			j.logf("Already running %s, and the latest release is %s: nothing to do.", cur.Tag(), target.Tag())
			return StatusDone
		}
	}
	j.logf("Updating from %s to %s.", cur.Tag(), target.Tag())

	sums, err := u.Source.Checksums(ctx, target)
	if errors.Is(err, release.ErrNotFound) {
		return j.failf("%s doesn't exist (no signed checksums were found for it).", target.Tag())
	}
	if err != nil {
		return j.failf("Not updating: %v", err)
	}
	j.logf("The checksums of %s are signed with the release key.", target.Tag())
	archive, err := u.Source.Archive(ctx, target, u.Arch, sums)
	if err != nil {
		return j.failf("Not updating: %v", err)
	}
	bin, err := release.ExtractBinary(archive)
	if err != nil {
		return j.failf("Not updating: %v", err)
	}
	j.logf("Downloaded %s and checked it against the signed checksum.", release.ArchiveName(target, u.Arch))

	newPath := u.Binary + ".new"
	if err := writeFileAtomic(newPath, bin, 0o755); err != nil {
		return j.failf("Writing the new binary: %v", err)
	}
	if err := j.checkBinary(ctx, newPath, target); err != nil {
		_ = os.Remove(newPath)
		return j.failf("Not updating: %v", err)
	}

	backup, err := j.backup(ctx, cur)
	if err != nil {
		_ = os.Remove(newPath)
		return j.failf("Backing up the database failed, so nothing was changed: %v", err)
	}
	// Lines from here on aren't in the backup, so a rollback that restores it writes them again.
	linesAtBackup := len(j.lines)
	j.logf("Backed up the database to %s.", backup)

	prev := u.Binary + ".prev"
	if err := copyFile(u.Binary, prev, 0o755); err != nil {
		_ = os.Remove(newPath)
		return j.failf("Keeping a copy of the current binary failed, so nothing was changed: %v", err)
	}
	if err := os.Rename(newPath, u.Binary); err != nil {
		_ = os.Remove(newPath)
		return j.failf("Putting the new binary in place failed, so nothing was changed: %v", err)
	}
	j.logf("Installed %s %s; the previous binary is %s.", u.Binary, target.Tag(), prev)

	if err := u.System.Systemctl(ctx, "restart", Service); err != nil {
		return j.rollback(ctx, fmt.Sprintf("Restarting %s failed: %v", Service, err), cur, prev, backup, linesAtBackup)
	}
	j.logf("Restarted %s; waiting up to %s for it to become healthy.", Service, u.healthWait())
	if err := j.waitHealthy(ctx); err != nil {
		return j.rollback(ctx, fmt.Sprintf("%s %s didn't become healthy: %v", Service, target.Tag(), err), cur, prev, backup, linesAtBackup)
	}
	j.logf("pihole-rbac %s is running and healthy.", target.Tag())
	return StatusDone
}

// checkBinary runs the new binary's version command: it must run on this host, be the version expected, and have
// the frontend embedded.
func (j *job) checkBinary(ctx context.Context, path string, want release.Version) error {
	out, err := j.u.System.BinaryVersion(ctx, path)
	if err != nil {
		return fmt.Errorf("the new binary doesn't run here: %v", err)
	}
	first, _, _ := strings.Cut(out, "\n")
	if !strings.HasPrefix(first, "pihole-rbac "+want.String()+" ") {
		return fmt.Errorf("the new binary reports %q, not %s", first, want.String())
	}
	if !strings.Contains(out, "\nfrontend: embedded") {
		return errors.New("the new binary was built without the frontend")
	}
	return nil
}

func (u *Updater) healthWait() time.Duration { return cmp.Or(u.HealthWait, 60*time.Second) }

// waitHealthy waits for the service to answer /healthz, then checks it is still answering a few seconds later, so a
// version that crashes soon after starting is caught.
func (j *job) waitHealthy(ctx context.Context) error {
	u := j.u
	ctx, cancel := context.WithTimeout(ctx, u.healthWait())
	defer cancel()
	poll := cmp.Or(u.HealthPoll, time.Second)
	var last error
	for {
		if last = u.System.Health(ctx); last == nil {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("not healthy after %s: %v", u.healthWait(), last)
		case <-time.After(poll):
		}
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("stopped waiting: %v", ctx.Err())
	case <-time.After(cmp.Or(u.Stable, 5*time.Second)):
	}
	if err := u.System.Health(ctx); err != nil {
		return fmt.Errorf("healthy at first, then not: %v", err)
	}
	return nil
}

// rollback puts the previous binary and the database backup back and starts the previous version. The database is
// restored because the new version may have migrated it; changes made since the backup, a minute or two at most,
// are lost.
func (j *job) rollback(ctx context.Context, cause string, cur release.Version, prev, backup string, linesAtBackup int) string {
	u := j.u
	j.logf("%s. Rolling back to %s.", cause, cur.Tag())
	// The rollback runs even if ctx has ended: leaving the new version half-installed is worse.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	defer cancel()

	var problems []string
	if err := u.System.Systemctl(ctx, "stop", Service); err != nil {
		problems = append(problems, fmt.Sprintf("stopping %s: %v", Service, err))
	}
	if err := copyFile(prev, u.Binary, 0o755); err != nil {
		problems = append(problems, fmt.Sprintf("restoring %s from %s: %v", u.Binary, prev, err))
	}

	// The connection must be closed before the file under it is replaced, and opened again afterwards.
	j.close()
	if err := j.restoreDB(backup); err != nil {
		problems = append(problems, fmt.Sprintf("restoring the database from %s: %v", backup, err))
	}
	if err := j.open(ctx); err != nil {
		fmt.Fprintf(u.out(), "reopening the database after the restore: %v\n", err)
	} else {
		// The backup was taken part-way through this request, so its log stops there: write the rest again.
		for _, line := range j.lines[linesAtBackup:] {
			if err := j.q.AppendUpdateLog(ctx, db.AppendUpdateLogParams{Line: line, ID: j.id}); err != nil {
				fmt.Fprintf(u.out(), "rewriting the log after the restore: %v\n", err)
				break
			}
		}
	}

	if err := u.System.Systemctl(ctx, "start", Service); err != nil {
		problems = append(problems, fmt.Sprintf("starting %s: %v", Service, err))
	} else if err := j.waitHealthy(ctx); err != nil {
		problems = append(problems, fmt.Sprintf("%s %s isn't healthy either: %v", Service, cur.Tag(), err))
	}
	if len(problems) > 0 {
		j.logf("The rollback needs attention: %s. The previous binary is %s and the database backup is %s.",
			strings.Join(problems, "; "), prev, backup)
		return StatusRolledBack
	}
	j.logf("Rolled back: %s is running and healthy again, with the database as it was before the update.", cur.Tag())
	return StatusRolledBack
}

// restoreDB replaces the database with the backup: copied beside it, given to the service user, then renamed into
// place, with the old WAL and shared-memory files removed so they can't be replayed onto it.
func (j *job) restoreDB(backup string) error {
	name, err := filepath.Rel(j.u.DataDir, backup)
	if err != nil {
		return err
	}
	if err := regularFile(j.root, name); err != nil {
		return err
	}
	b, err := j.root.ReadFile(name)
	if err != nil {
		return err
	}
	tmp := store.FileName + ".restore"
	if err := writeFileAtomicIn(j.root, tmp, b, 0o600); err != nil {
		return err
	}
	if err := j.u.System.Chown(j.root, tmp); err != nil {
		_ = j.root.Remove(tmp)
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := j.root.Remove(store.FileName + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			_ = j.root.Remove(tmp)
			return err
		}
	}
	return j.root.Rename(tmp, store.FileName)
}

// backup writes the database to backups/<version>-<time>.db with VACUUM INTO, owned by the service user, and keeps
// the newest KeepBackups of the updater's backups. The app's own pre-migrate-* backups are left alone.
func (j *job) backup(ctx context.Context, cur release.Version) (string, error) {
	u := j.u
	dirName := u.backupsName()
	if err := j.root.Mkdir(dirName, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	if fi, err := j.root.Lstat(dirName); err != nil {
		return "", err
	} else if !fi.IsDir() {
		return "", fmt.Errorf("%s isn't a directory (%s): refusing to use it", store.BackupDir(u.DataDir), fi.Mode().Type())
	}
	// Mkdir's mode is narrowed by the umask, which is 0077 under pihole-rbac-update.service; the app creates the
	// directory 0750 (its umask is 0027), so the updater sets the same mode whoever created it.
	if err := j.root.Chmod(dirName, 0o750); err != nil {
		return "", err
	}
	if err := u.System.Chown(j.root, dirName); err != nil {
		return "", err
	}
	name := filepath.Join(dirName, cur.Tag()+"-"+u.now().UTC().Format(store.BackupTimeFormat)+".db")
	if _, err := j.root.Lstat(name); err == nil {
		return "", fmt.Errorf("%s already exists", name)
	}
	path := filepath.Join(u.DataDir, name)
	if _, err := j.d.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return "", err
	}
	// SQLite wrote the file by path; make sure what is there now is that file before changing it.
	if err := regularFile(j.root, name); err != nil {
		return "", err
	}
	if err := j.root.Chmod(name, 0o600); err != nil {
		return "", err
	}
	if err := u.System.Chown(j.root, name); err != nil {
		return "", err
	}
	if err := pruneBackups(j.root, dirName, cmp.Or(u.KeepBackups, 5)); err != nil {
		j.logf("Removing old update backups: %v", err)
	}
	return path, nil
}

// pruneBackups keeps the newest keep of the updater's backups (v<version>-<time>.db) in dir, inside root, by the time
// in their names.
func pruneBackups(root *os.Root, dir string, keep int) error {
	d, err := root.Open(dir)
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	timeLen := len(store.BackupTimeFormat)
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasPrefix(n, "v") || !strings.HasSuffix(n, ".db") {
			continue
		}
		stem := strings.TrimSuffix(n, ".db")
		if len(stem) < timeLen+2 || stem[len(stem)-timeLen-1] != '-' {
			continue
		}
		if _, err := time.Parse(store.BackupTimeFormat, stem[len(stem)-timeLen:]); err != nil {
			continue
		}
		names = append(names, n)
	}
	if len(names) <= keep {
		return nil
	}
	timeOf := func(n string) string {
		stem := strings.TrimSuffix(n, ".db")
		return stem[len(stem)-timeLen:]
	}
	slices.SortFunc(names, func(a, b string) int { return cmp.Compare(timeOf(a), timeOf(b)) })
	var errs []error
	for _, n := range names[:len(names)-keep] {
		errs = append(errs, root.Remove(filepath.Join(dir, n)))
	}
	return errors.Join(errs...)
}

// writeFileAtomicIn is writeFileAtomic for a file inside root. The temporary file is created exclusively, so a
// symlink planted under its name makes it fail rather than write through it, and its mode is set on the open file.
func writeFileAtomicIn(root *os.Root, name string, b []byte, mode fs.FileMode) error {
	tmp := name + ".tmp"
	if err := root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	merr := f.Chmod(mode) // the umask may have narrowed it
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, merr, serr, cerr); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return root.Rename(tmp, name)
}

// writeFileAtomic writes b to a temporary file beside path and renames it into place.
func writeFileAtomic(path string, b []byte, mode fs.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, werr := io.Copy(f, bytes.NewReader(b))
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // the umask may have narrowed it
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// copyFile copies src to dst through a temporary file, so dst is either the old file or a complete copy.
func copyFile(src, dst string, mode fs.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b, mode)
}
