// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package syslogfwd forwards the audit log to syslog collectors (Graylog, Wazuh, rsyslog and the like).
//
// Format writes one audit row as an RFC 5424 message by hand: Go's log/syslog is Unix-only, frozen, and has no TLS,
// and the format is a fixed standard. The message text is the row as JSON, with no structured data. Writer sends
// messages over TLS, TCP or UDP, and Forwarder reads audit_log from a cursor and sends what is new, so nothing is
// lost while a collector is down.
package syslogfwd

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Message constants. Facility 13 is "log audit".
const (
	Facility = 13
	AppName  = "pihole-rbac"

	// UDPLimit and StreamLimit are the most bytes a message may have, framing excluded. A row over the limit is sent
	// with its detail replaced by {"truncated":true}: its id still finds it in the audit page.
	UDPLimit    = 2000
	StreamLimit = 64 << 10

	// truncatedField caps the free text fields of a truncated row, so it fits whatever the limit.
	truncatedField = 256
)

const timeLayout = "2006-01-02T15:04:05.000Z"

// Row is one audit_log row.
type Row struct {
	ID         int64
	At         time.Time
	UserID     int64 // 0 when the row has no user
	User       string
	Action     string
	Target     string
	InstanceID int64 // 0 when the row isn't about one instance
	Instance   string
	Result     string
	Detail     string // JSON, as stored
	IP         string
}

// RowFromAudit converts a stored row.
func RowFromAudit(r db.AuditLog) Row {
	return Row{ID: r.ID, At: store.FromMillis(r.At), UserID: r.UserID.Int64, User: r.Username, Action: r.Action,
		Target: r.Target, InstanceID: r.InstanceID.Int64, Instance: r.InstanceName, Result: r.Result, Detail: r.Detail, IP: r.Ip}
}

// Severity is 4 (warning) for a failure and 6 (informational) for anything else.
func Severity(result string) int {
	if result == audit.ResultFailure {
		return 4
	}
	return 6
}

type jsonRow struct {
	ID         int64           `json:"id"`
	Time       string          `json:"time"`
	UserID     *int64          `json:"user_id"`
	User       string          `json:"user"`
	Action     string          `json:"action"`
	Target     string          `json:"target"`
	InstanceID *int64          `json:"instance_id"`
	Instance   string          `json:"instance"`
	Result     string          `json:"result"`
	IP         string          `json:"ip"`
	Detail     json.RawMessage `json:"detail"`
}

// Format returns the RFC 5424 message for r, without framing: <PRI>1 TIMESTAMP HOSTNAME pihole-rbac - MSGID - JSON.
// The timestamp is the row's own time in UTC, and the message ID is the action. limit is the most bytes the message
// may have (UDPLimit or StreamLimit): a longer one is sent with its detail replaced and its text fields shortened.
func Format(r Row, hostname string, limit int) []byte {
	m := message(r, hostname, false)
	if limit > 0 && len(m) > limit {
		m = message(r, hostname, true)
	}
	return m
}

func message(r Row, hostname string, truncate bool) []byte {
	j := jsonRow{ID: r.ID, Time: r.At.UTC().Format(timeLayout), User: r.User, Action: r.Action, Target: r.Target,
		Instance: r.Instance, Result: r.Result, IP: r.IP, Detail: json.RawMessage(r.Detail)}
	if r.UserID != 0 {
		j.UserID = &r.UserID
	}
	if r.InstanceID != 0 {
		j.InstanceID = &r.InstanceID
	}
	if truncate {
		j.User, j.Target, j.Instance, j.IP = shorten(j.User), shorten(j.Target), shorten(j.Instance), shorten(j.IP)
		j.Detail = json.RawMessage(`{"truncated":true}`)
	} else if len(j.Detail) == 0 || !json.Valid(j.Detail) {
		j.Detail = json.RawMessage(`{}`)
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(j); err != nil { // only an invalid detail could fail, and it was checked
		body.Reset()
		body.WriteString(`{"error":"row could not be encoded"}`)
	}
	text := bytes.TrimSuffix(body.Bytes(), []byte("\n"))
	if !utf8.Valid(text) {
		text = bytes.ToValidUTF8(text, []byte("�"))
	}
	return header(Severity(r.Result), r.At, hostname, r.Action, text)
}

func header(severity int, at time.Time, hostname, msgID string, text []byte) []byte {
	var b bytes.Buffer
	b.WriteByte('<')
	b.WriteString(strconv.Itoa(Facility*8 + severity))
	b.WriteString(">1 ")
	b.WriteString(at.UTC().Format(timeLayout))
	b.WriteByte(' ')
	b.WriteString(CleanHostname(hostname))
	b.WriteByte(' ')
	b.WriteString(AppName)
	b.WriteString(" - ")
	b.WriteString(cleanMsgID(msgID))
	b.WriteString(" - ")
	b.Write(text)
	return b.Bytes()
}

// FormatTest returns the message a destination's Test sends. Its message ID is test, and it is not an audit row.
func FormatTest(now time.Time, hostname string) []byte {
	return header(6, now, hostname, "test", []byte(`{"message":"pihole-rbac log forwarding test"}`))
}

// Frame adds octet-counting framing (RFC 6587, as RFC 5425 requires over TLS) for a stream.
func Frame(msg []byte) []byte {
	out := make([]byte, 0, len(msg)+8)
	out = strconv.AppendInt(out, int64(len(msg)), 10)
	out = append(out, ' ')
	return append(out, msg...)
}

// CleanHostname returns s if it is a valid RFC 5424 HOSTNAME (1 to 255 printable ASCII characters, no spaces), or "-".
func CleanHostname(s string) string {
	if !printable(s, 255) {
		return "-"
	}
	return s
}

// Hostname is this host's name, cleaned for a message.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "-"
	}
	return CleanHostname(h)
}

// cleanMsgID returns s if it is a valid MSGID (1 to 32 printable ASCII characters), or "-".
func cleanMsgID(s string) string {
	if !printable(s, 32) {
		return "-"
	}
	return s
}

func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// shorten cuts s to truncatedField bytes at a character boundary.
func shorten(s string) string {
	if len(s) <= truncatedField {
		return s
	}
	cut := truncatedField
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.ToValidUTF8(s[:cut], "") + "…"
}
