// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package syslogfwd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
)

// parts splits a message into its header fields and the JSON text.
type parts struct {
	pri, version, ts, host, app, procid, msgid, sd, text string
}

func split(t *testing.T, msg []byte) parts {
	t.Helper()
	f := strings.SplitN(string(msg), " ", 8)
	if len(f) != 8 {
		t.Fatalf("message has %d fields: %q", len(f), msg)
	}
	if !strings.HasPrefix(f[0], "<") || !strings.HasSuffix(f[0], ">1") {
		t.Fatalf("PRI and version: %q", f[0])
	}
	return parts{pri: strings.TrimSuffix(strings.TrimPrefix(f[0], "<"), ">1"), version: "1", ts: f[1], host: f[2], app: f[3],
		procid: f[4], msgid: f[5], sd: f[6], text: f[7]}
}

var sample = Row{
	ID: 42, At: time.Date(2026, 11, 18, 22, 30, 5, 123_000_000, time.UTC), UserID: 5, User: "alice", Action: "domain_add",
	Target: "i-7", InstanceID: 7, Instance: "pihole1", Result: "success", Detail: `{"domain":"a.example","via_token":"ha"}`, IP: "10.0.0.5",
}

func TestFormat(t *testing.T) {
	fail := sample
	fail.Result, fail.UserID, fail.InstanceID, fail.Instance = "failure", 0, 0, ""
	for name, tc := range map[string]struct {
		row      Row
		host     string
		wantPRI  string
		wantHost string
	}{
		"a success is informational": {sample, "pihole-rbac.lab", "110", "pihole-rbac.lab"},
		"a failure is a warning":     {fail, "pihole-rbac.lab", "108", "pihole-rbac.lab"},
		"an empty hostname":          {sample, "", "110", "-"},
		"a hostname with a space":    {sample, "my host", "110", "-"},
		"a hostname outside ASCII":   {sample, "hôst", "110", "-"},
		"a hostname over 255":        {sample, strings.Repeat("a", 256), "110", "-"},
	} {
		t.Run(name, func(t *testing.T) {
			p := split(t, Format(tc.row, tc.host, StreamLimit))
			if p.pri != tc.wantPRI || p.host != tc.wantHost || p.app != "pihole-rbac" || p.procid != "-" || p.sd != "-" {
				t.Errorf("header: %+v", p)
			}
			if p.ts != "2026-11-18T22:30:05.123Z" {
				t.Errorf("timestamp %q is not the row's own time", p.ts)
			}
			if p.msgid != "domain_add" {
				t.Errorf("message ID %q, want the action", p.msgid)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(p.text), &got); err != nil {
				t.Fatalf("text isn't JSON: %v: %q", err, p.text)
			}
			if got["id"] != float64(42) || got["action"] != "domain_add" || got["result"] != tc.row.Result || got["ip"] != "10.0.0.5" {
				t.Errorf("row: %v", got)
			}
			if _, ok := got["detail"].(map[string]any); !ok {
				t.Errorf("detail is not an object: %v", got["detail"])
			}
		})
	}
}

func TestFormatOptionalIDs(t *testing.T) {
	r := sample
	r.UserID, r.InstanceID = 0, 0
	var got map[string]any
	if err := json.Unmarshal([]byte(split(t, Format(r, "h", StreamLimit)).text), &got); err != nil {
		t.Fatal(err)
	}
	if v, ok := got["user_id"]; !ok || v != nil {
		t.Errorf("user_id %v (present %v), want null", v, ok)
	}
	if v, ok := got["instance_id"]; !ok || v != nil {
		t.Errorf("instance_id %v (present %v), want null", v, ok)
	}
	got = nil
	if err := json.Unmarshal([]byte(split(t, Format(sample, "h", StreamLimit)).text), &got); err != nil {
		t.Fatal(err)
	}
	if got["user_id"] != float64(5) || got["instance_id"] != float64(7) {
		t.Errorf("ids: %v %v", got["user_id"], got["instance_id"])
	}
}

// Every action the app writes is a valid message ID: printable ASCII, 32 characters at most.
func TestEveryActionIsAMessageID(t *testing.T) {
	for _, a := range audit.Actions() {
		if got := cleanMsgID(a.Name); got != a.Name {
			t.Errorf("action %q would be sent as message ID %q", a.Name, got)
		}
	}
	if cleanMsgID("") != "-" || cleanMsgID("two words") != "-" || cleanMsgID(strings.Repeat("a", 33)) != "-" {
		t.Error("an invalid message ID wasn't replaced by -")
	}
}

// A value from a request (a login username, a Pi-hole comment) can hold anything. The message must stay one message.
func TestFormatHostileValues(t *testing.T) {
	r := sample
	r.User = "mallory\n<110>1 2026-11-18T00:00:00.000Z host pihole-rbac - login - {\"forged\":true}"
	r.Target = "a\r\nb\x00c\x1b[31m"
	r.Instance = "bad\xffutf8\xc3"
	r.Detail = `{"comment":"line one\nline two"}`
	msg := Format(r, "h", StreamLimit)
	if strings.ContainsAny(string(msg), "\r\n") {
		t.Errorf("a newline reached the message: %q", msg)
	}
	if !utf8.Valid(msg) {
		t.Errorf("message isn't valid UTF-8: %q", msg)
	}
	p := split(t, msg)
	var got map[string]any
	if err := json.Unmarshal([]byte(p.text), &got); err != nil {
		t.Fatalf("text isn't JSON: %v", err)
	}
	if got["user"] != r.User || !strings.Contains(got["instance"].(string), "�") {
		t.Errorf("values: %q %q", got["user"], got["instance"])
	}
}

func TestFormatDetailThatIsNotJSON(t *testing.T) {
	for _, d := range []string{"", "not json", `{"unterminated":`} {
		r := sample
		r.Detail = d
		p := split(t, Format(r, "h", StreamLimit))
		var got struct{ Detail map[string]any }
		if err := json.Unmarshal([]byte(p.text), &got); err != nil || got.Detail == nil {
			t.Errorf("detail %q: %v, %q", d, err, p.text)
		}
	}
}

func TestFormatTruncation(t *testing.T) {
	r := sample
	r.Detail = `{"domains":"` + strings.Repeat("x", 5000) + `"}`
	r.Target = strings.Repeat("t", 1500)

	udp := Format(r, "h", UDPLimit)
	if len(udp) > UDPLimit {
		t.Errorf("a UDP message is %d bytes, over %d", len(udp), UDPLimit)
	}
	var got struct {
		ID     int64
		Target string
		Detail map[string]any
	}
	if err := json.Unmarshal([]byte(split(t, udp).text), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 42 || got.Detail["truncated"] != true || len(got.Detail) != 1 {
		t.Errorf("a truncated row: id %d, detail %v", got.ID, got.Detail)
	}
	if len(got.Target) > 300 {
		t.Errorf("target kept %d bytes", len(got.Target))
	}

	stream := Format(r, "h", StreamLimit)
	if !strings.Contains(string(stream), strings.Repeat("x", 5000)) {
		t.Error("a row under the stream limit lost its detail")
	}
	r.Detail = `{"domains":"` + strings.Repeat("x", 70000) + `"}`
	if big := Format(r, "h", StreamLimit); len(big) > StreamLimit || !strings.Contains(string(big), `"truncated":true`) {
		t.Errorf("a row over the stream limit: %d bytes", len(big))
	}
}

func TestFrame(t *testing.T) {
	if got := string(Frame([]byte("hello"))); got != "5 hello" {
		t.Errorf("got %q", got)
	}
	if got := string(Frame(nil)); got != "0 " {
		t.Errorf("got %q", got)
	}
}

func TestFormatTest(t *testing.T) {
	p := split(t, FormatTest(time.Date(2026, 11, 18, 1, 2, 3, 0, time.UTC), "h"))
	if p.msgid != "test" || p.pri != "110" || !strings.Contains(p.text, "log forwarding test") {
		t.Errorf("%+v", p)
	}
}

func TestSeverity(t *testing.T) {
	if Severity("success") != 6 || Severity("failure") != 4 || Severity("") != 6 {
		t.Error("severities")
	}
}

func TestShortenKeepsCharacters(t *testing.T) {
	s := strings.Repeat("é", 200) // 400 bytes
	got := shorten(s)
	if !utf8.ValidString(got) || len(got) > 300 {
		t.Errorf("shorten: valid %v, %d bytes", utf8.ValidString(got), len(got))
	}
}
