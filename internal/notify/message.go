// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"errors"
	"fmt"
	"html"
	"strings"
	"unicode"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// EventProtectedGroupAdd is the one event that isn't an audit action: a client_update that put a client in a
// protected group carries protected_added in its detail, and channels can ask for that alone.
const EventProtectedGroupAdd = "protected_group_add"

type style int

const (
	plain style = iota
	bold
	code
)

type part struct {
	text  string
	style style
}

// Message is a notification built from parts, so values from outside (usernames typed into a failed login, Pi-hole
// comments, domain names) can only ever be text: each renderer escapes them for its format.
type Message struct {
	parts []part
}

// Text adds plain text.
func (m *Message) Text(s string) *Message { return m.add(s, plain) }

// Bold adds bold text.
func (m *Message) Bold(s string) *Message { return m.add(s, bold) }

// Code adds text in a code span.
func (m *Message) Code(s string) *Message { return m.add(s, code) }

func (m *Message) add(s string, st style) *Message {
	m.parts = append(m.parts, part{text: clean(s), style: st})
	return m
}

// maxValue caps one value in a message; Discord takes 2,000 characters in all.
const maxValue = 200

// clean makes a value one short line: control characters (a newline could fake a second line of the message) become
// spaces, and long values are cut.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	if r := []rune(s); len(r) > maxValue {
		s = string(r[:maxValue-1]) + "…"
	}
	return s
}

// discordEscaper escapes everything Discord's markdown gives meaning to, outside code spans.
var discordEscaper = func() *strings.Replacer {
	var pairs []string
	for _, c := range []string{`\`, "*", "_", "~", "`", "|", ">", "#", "-", "[", "]", "(", ")", ":", "<", "@"} {
		pairs = append(pairs, c, `\`+c)
	}
	return strings.NewReplacer(pairs...)
}()

// maxDiscord is Discord's limit on a message's content, in characters.
const maxDiscord = 2000

// Discord renders the message as Discord markdown. Mentions are switched off in the payload as well (see send.go), so
// even an unescaped @everyone couldn't ping anyone.
func (m *Message) Discord() string {
	var b strings.Builder
	for _, p := range m.parts {
		switch p.style {
		case plain:
			b.WriteString(discordEscaper.Replace(p.text))
		case bold:
			b.WriteString("**" + discordEscaper.Replace(p.text) + "**")
		case code:
			// Inside a code span nothing is formatted, so only a backtick (which would end it) needs handling.
			t := strings.ReplaceAll(p.text, "`", "'")
			if t == "" {
				t = " "
			}
			b.WriteString("`" + t + "`")
		}
	}
	s := b.String()
	if r := []rune(s); len(r) > maxDiscord {
		s = string(r[:maxDiscord-1]) + "…"
	}
	return s
}

// Plain renders the message as plain text, for Matrix's body and for logs.
func (m *Message) Plain() string {
	var b strings.Builder
	for _, p := range m.parts {
		b.WriteString(p.text)
	}
	return b.String()
}

// HTML renders the message for Matrix's formatted_body, every value escaped.
func (m *Message) HTML() string {
	var b strings.Builder
	for _, p := range m.parts {
		t := html.EscapeString(p.text)
		switch p.style {
		case plain:
			b.WriteString(t)
		case bold:
			b.WriteString("<strong>" + t + "</strong>")
		case code:
			b.WriteString("<code>" + t + "</code>")
		}
	}
	return b.String()
}

// itemKeys are the detail keys that name what an action was about, in the order tried. Only these are copied into a
// message: the rest of a detail can be long, and none of it is needed to know what happened.
var itemKeys = []string{"domain", "client", "username", "name", "summary"}

// ForEntry describes an audit entry in one line: who did what, to what, on which instance, and how it went. A failure
// gives its error code, never the error's text, which can name internal addresses; the message goes to a third party.
func ForEntry(e audit.Entry) *Message {
	m := &Message{}
	m.Bold(e.Username).Text(" " + strings.ReplaceAll(e.Action, "_", " "))
	if e.Target != "" {
		m.Text(" on ").Code(e.Target)
	}
	if e.InstanceName != "" {
		m.Text(" (").Text(e.InstanceName).Text(")")
	}
	for _, k := range itemKeys {
		if v, ok := e.Detail[k].(string); ok && v != "" {
			m.Text(": ").Code(v)
			break
		}
	}
	if e.Err != nil {
		m.Text(" — ").Bold("failed").Text(" (" + ErrorCode(e) + ")")
	} else {
		m.Text(" — succeeded")
	}
	return m
}

// ErrorCode is the code of an entry's failure: the error_code a Pi-hole write records, the code of a refusal, or
// "error" when there is neither.
func ErrorCode(e audit.Entry) string {
	if c, ok := e.Detail["error_code"].(string); ok && c != "" {
		return clean(c)
	}
	var re *rbac.Error
	if errors.As(e.Err, &re) && re.Code != "" {
		return string(re.Code)
	}
	return "error"
}

// ProtectedGroups returns the protected Pi-hole groups a client_update added the client to, from its detail.
func ProtectedGroups(e audit.Entry) []string {
	if e.Action != audit.ActionClientUpdate || e.Err != nil {
		return nil
	}
	return stringList(e.Detail["protected_added"])
}

// stringList reads a list of strings from an audit detail value, as built in Go or as read back from JSON.
func stringList(v any) []string {
	var out []string
	switch v := v.(type) {
	case []string:
		out = v
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ProtectedAlert is one client added to protected Pi-hole groups.
type ProtectedAlert struct {
	Client string
	Groups []string
}

// ProtectedClient is how a client_reset row lists a client its run put in protected groups, under "protected".
type ProtectedClient struct {
	Client string   `json:"client"`
	Groups []string `json:"groups"`
}

// ProtectedAlerts returns an alert for each client an entry added to protected Pi-hole groups: the client of a
// successful client_update, or each client a client_reset put in one. A reset that failed for some clients still
// reset the others, and lists only those.
func ProtectedAlerts(e audit.Entry) []ProtectedAlert {
	switch e.Action {
	case audit.ActionClientUpdate:
		if groups := ProtectedGroups(e); len(groups) > 0 {
			client, _ := e.Detail["client"].(string)
			return []ProtectedAlert{{Client: client, Groups: groups}}
		}
	case audit.ActionClientReset:
		var out []ProtectedAlert
		switch v := e.Detail["protected"].(type) {
		case []ProtectedClient:
			for _, p := range v {
				if len(p.Groups) > 0 {
					out = append(out, ProtectedAlert{Client: p.Client, Groups: p.Groups})
				}
			}
		case []any:
			for _, item := range v {
				m, _ := item.(map[string]any)
				client, _ := m["client"].(string)
				if groups := stringList(m["groups"]); len(groups) > 0 {
					out = append(out, ProtectedAlert{Client: client, Groups: groups})
				}
			}
		}
		return out
	}
	return nil
}

// ForProtectedGroup is the alert for a client_update that added its client to protected groups.
func ForProtectedGroup(e audit.Entry, groups []string) *Message {
	client, _ := e.Detail["client"].(string)
	return ForProtectedAlert(e, ProtectedAlert{Client: client, Groups: groups})
}

// ForProtectedAlert is the alert for one client added to protected groups.
func ForProtectedAlert(e audit.Entry, a ProtectedAlert) *Message {
	m := &Message{}
	m.Text("🚨 ").Bold(e.Username).Text(" added client ")
	client, groups := a.Client, a.Groups
	m.Code(client).Text(" to protected group")
	if len(groups) > 1 {
		m.Text("s")
	}
	m.Text(" ")
	for i, g := range groups {
		if i > 0 {
			m.Text(", ")
		}
		m.Bold(g)
	}
	if e.InstanceName != "" {
		m.Text(" on ").Text(e.InstanceName)
	}
	return m
}

// ForTest is the message Send test posts.
func ForTest(channel, by string) *Message {
	m := &Message{}
	return m.Text("Test message from pihole-rbac for channel ").Bold(channel).Text(fmt.Sprintf(", sent by %s.", by))
}
