// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

const (
	defaultAuditPage = 50
	maxAuditPage     = 200
	maxAuditExport   = 50000 // rows in one CSV export
	auditExportChunk = 1000  // rows read from the database at a time while exporting
	maxAuditActions  = 50
	maxAuditUser     = 256
	maxAuditTarget   = 512
)

var auditActionPattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// auditFilter is the filters shared by the list and the export, checked and ready for ListAudit.
type auditFilter struct {
	params db.ListAuditParams
}

// newAuditFilter checks the filters. The generated decoder doesn't enforce lengths or patterns, so it's done here.
func newAuditFilter(user *string, actions *[]string, target *string, instanceID *int64, result *string,
	from, to *time.Time) (auditFilter, error) {
	var f auditFilter
	p := &f.params
	if user != nil {
		if len(*user) > maxAuditUser {
			return f, invalid("user", "A username is at most %d bytes.", maxAuditUser)
		}
		p.Username = *user
	}
	list := []string{}
	if actions != nil {
		if len(*actions) > maxAuditActions {
			return f, invalid("action", "At most %d actions.", maxAuditActions)
		}
		for _, a := range *actions {
			if !auditActionPattern.MatchString(a) {
				return f, invalid("action", "%q isn't an action name.", a)
			}
			list = append(list, a)
		}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return f, err
	}
	p.Actions = string(b)
	if target != nil {
		if len(*target) > maxAuditTarget {
			return f, invalid("target", "A target is at most %d bytes.", maxAuditTarget)
		}
		p.Target = *target
	}
	if instanceID != nil {
		if *instanceID < 1 {
			return f, invalid("instance_id", "An instance ID is a positive number.")
		}
		p.InstanceID = *instanceID
	}
	if result != nil {
		if *result != "success" && *result != "failure" {
			return f, invalid("result", "The result is success or failure.")
		}
		p.Result = *result
	}
	// A time before 1970 would be stored as 0, which the query reads as no filter; nothing in the log is that old.
	if from != nil && from.UnixMilli() > 0 {
		p.FromAt = store.Millis(*from)
	}
	if to != nil {
		if to.UnixMilli() <= 0 {
			return f, invalid("to", "That is before anything in the log.")
		}
		p.ToAt = store.Millis(*to)
	}
	if p.FromAt != 0 && p.ToAt != 0 && p.ToAt <= p.FromAt {
		return f, invalid("to", "The end of the time range must be after its start.")
	}
	return f, nil
}

// page reads up to limit entries older than beforeID (0 for the newest).
func (f auditFilter) page(ctx context.Context, q *db.Queries, beforeID int64, limit int) ([]db.AuditLog, error) {
	p := f.params
	p.BeforeID, p.RowLimit = beforeID, int64(limit)
	return q.ListAudit(ctx, p)
}

// ListAudit lists audit entries, newest first. The cursor is the ID of the previous page's last entry,
// base64url-encoded; IDs only grow, so a page never repeats or skips entries written meanwhile.
func (s *Server) ListAudit(ctx context.Context, req gen.ListAuditRequestObject) (gen.ListAuditResponseObject, error) {
	p := req.Params
	f, err := newAuditFilter(p.User, p.Action, p.Target, p.InstanceId, (*string)(p.Result), p.From, p.To)
	if err != nil {
		return nil, err
	}
	limit := defaultAuditPage
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > maxAuditPage {
		return nil, invalid("limit", "The limit is 1 to %d.", maxAuditPage)
	}
	var before int64
	if p.Cursor != nil && *p.Cursor != "" {
		if before, err = decodeAuditCursor(*p.Cursor); err != nil {
			return nil, invalid("cursor", "That cursor isn't one this server gave out.")
		}
	}
	// One more than asked for says whether there is another page.
	rows, err := f.page(ctx, s.Store.Read(), before, limit+1)
	if err != nil {
		return nil, err
	}
	out := gen.AuditList{Entries: make([]gen.AuditEntry, 0, min(len(rows), limit))}
	if len(rows) > limit {
		rows = rows[:limit]
		c := encodeAuditCursor(rows[len(rows)-1].ID)
		out.NextCursor = &c
	}
	for _, r := range rows {
		out.Entries = append(out.Entries, auditJSON(r))
	}
	return gen.ListAudit200JSONResponse(out), nil
}

func auditJSON(r db.AuditLog) gen.AuditEntry {
	e := gen.AuditEntry{
		Id: r.ID, At: store.FromMillis(r.At).UTC(), Username: r.Username, Action: r.Action, Target: r.Target,
		InstanceName: r.InstanceName, Result: gen.AuditEntryResult(r.Result), Ip: r.Ip, Detail: map[string]any{},
	}
	if r.UserID.Valid {
		id := r.UserID.Int64
		e.UserId = &id
	}
	if r.InstanceID.Valid {
		id := r.InstanceID.Int64
		e.InstanceId = &id
	}
	// The column is checked to be valid JSON; a detail that isn't an object (never written by this app) is shown empty.
	_ = json.Unmarshal([]byte(r.Detail), &e.Detail)
	return e
}

func encodeAuditCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("a:" + strconv.FormatInt(id, 10)))
}

func decodeAuditCursor(c string) (int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, err
	}
	n, ok := strings.CutPrefix(string(b), "a:")
	if !ok {
		return 0, errors.New("bad cursor")
	}
	id, err := strconv.ParseInt(n, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("bad cursor")
	}
	return id, nil
}

var auditCSVHeader = []string{"id", "time", "user", "action", "target", "instance_id", "instance", "result", "ip", "detail"}

// ExportAudit writes the matching entries as CSV, newest first, at most maxAuditExport of them. The first chunk is
// read before answering, so a database error is still an error response; the rest is streamed.
func (s *Server) ExportAudit(ctx context.Context, req gen.ExportAuditRequestObject) (gen.ExportAuditResponseObject, error) {
	p := req.Params
	f, err := newAuditFilter(p.User, p.Action, p.Target, p.InstanceId, (*string)(p.Result), p.From, p.To)
	if err != nil {
		return nil, err
	}
	q := s.Store.Read()
	first, err := f.page(ctx, q, 0, auditExportChunk)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeAuditCSV(ctx, pw, first, func(before int64, limit int) ([]db.AuditLog, error) {
			return f.page(ctx, q, before, limit)
		}))
	}()
	name := "attachment; filename=\"pihole-rbac-audit-" + time.Now().UTC().Format("20060102-150405") + ".csv\""
	return gen.ExportAudit200TextcsvResponse{Body: pr, Headers: gen.ExportAudit200ResponseHeaders{ContentDisposition: &name}}, nil
}

// writeAuditCSV writes the header and rows, starting with first and reading more with next until maxAuditExport rows
// are written or there are none left. It returns as soon as a write fails, as it does when the client goes away and
// the response's reader is closed.
func writeAuditCSV(ctx context.Context, w io.Writer, first []db.AuditLog,
	next func(before int64, limit int) ([]db.AuditLog, error)) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(auditCSVHeader); err != nil {
		return err
	}
	rows, written := first, 0
	for len(rows) > 0 {
		for _, r := range rows {
			if written == maxAuditExport {
				break
			}
			if err := cw.Write(auditCSVRecord(r)); err != nil {
				return err
			}
			written++
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return err
		}
		if written == maxAuditExport || len(rows) < auditExportChunk {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		if rows, err = next(rows[len(rows)-1].ID, min(auditExportChunk, maxAuditExport-written)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func auditCSVRecord(r db.AuditLog) []string {
	instanceID := ""
	if r.InstanceID.Valid {
		instanceID = strconv.FormatInt(r.InstanceID.Int64, 10)
	}
	rec := []string{
		strconv.FormatInt(r.ID, 10), store.FromMillis(r.At).UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		r.Username, r.Action, r.Target, instanceID, r.InstanceName, r.Result, r.Ip, r.Detail,
	}
	for i := range rec {
		rec[i] = csvSafe(rec[i])
	}
	return rec
}

// csvSafe stops a spreadsheet treating a cell as a formula. Usernames typed into a failed login, Pi-hole comments and
// domain names reach the log unchanged, so any of them could start with "=HYPERLINK(...)". A leading apostrophe makes
// Excel, LibreOffice and Google Sheets show the cell as text. Invalid UTF-8 is replaced, so the file is always UTF-8.
func csvSafe(v string) string {
	if !utf8.ValidString(v) {
		v = strings.ToValidUTF8(v, "�")
	}
	if v != "" {
		switch v[0] {
		case '=', '+', '-', '@', '\t', '\r':
			return "'" + v
		}
	}
	return v
}
