// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

func TestRejections(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name     string
		handler  func(w http.ResponseWriter, r *http.Request) bool
		call     func(c *piholeapi.Client) error
		wantMsg  string
		wantItem string
	}{
		{
			name: "duplicate add is listed under processed.errors",
			call: func(c *piholeapi.Client) error {
				d := piholeapi.DomainEntry{Domain: "ads.example", Type: "deny", Kind: "exact"}
				if _, err := c.AddDomain(ctx, d); err != nil {
					t.Fatalf("first add: %v", err)
				}
				_, err := c.AddDomain(ctx, d)
				return err
			},
			wantMsg: "UNIQUE constraint failed", wantItem: "ads.example",
		},
		{
			name: "400 with an error body",
			call: func(c *piholeapi.Client) error {
				_, err := c.AddDomain(ctx, piholeapi.DomainEntry{Domain: "not a domain", Type: "deny", Kind: "exact"})
				return err
			},
			wantMsg: "Invalid domain",
		},
		{
			name: "400 with a hint, and control characters in the message",
			handler: func(w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"key":"bad_request","message":"Bad\nAUDIT user=\"x\"","hint":"use a  regex"}}`)
				return true
			},
			call: func(c *piholeapi.Client) error {
				_, err := c.UpdateClientGroups(ctx, "10.0.0.5", "", nil)
				return err
			},
			wantMsg: `Bad AUDIT user="x" (use a regex)`,
		},
		{
			name: "numeric item",
			handler: func(w http.ResponseWriter, r *http.Request) bool {
				_, _ = io.WriteString(w, `{"processed":{"errors":[{"item":7,"error":"nope"}],"success":[]}}`)
				return true
			},
			call: func(c *piholeapi.Client) error {
				_, err := c.UpdateClientGroups(ctx, "10.0.0.5", "", nil)
				return err
			},
			wantMsg: "nope", wantItem: "7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			if tt.handler != nil {
				ph.Handle(tt.handler)
			}
			c := newClient(t, ph.URL)
			err := tt.call(c)
			var re *piholeapi.RejectedError
			if !errors.As(err, &re) || !errors.Is(err, piholeapi.ErrRejected) {
				t.Fatalf("err = %v, want a RejectedError", err)
			}
			if !strings.Contains(re.Message, tt.wantMsg) || re.Item != tt.wantItem {
				t.Errorf("message %q, item %q; want message containing %q, item %q", re.Message, re.Item, tt.wantMsg, tt.wantItem)
			}
			if strings.ContainsAny(re.Message, "\n\r") {
				t.Errorf("message %q has a line break", re.Message)
			}
			if got := piholeapi.Kind(err); got != piholeapi.CodeRejected {
				t.Errorf("Kind = %q, want %q", got, piholeapi.CodeRejected)
			}
			if piholeapi.Down(err) {
				t.Error("a rejection counts as down")
			}
		})
	}
}

func TestStatusErrorKeepsPiholeMessage(t *testing.T) {
	ph := piholetest.New(t, password)
	ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"key":"database_error","message":"`+strings.Repeat("x", 1000)+`","hint":null}}`)
		return true
	})
	_, err := newClient(t, ph.URL).GetStatus(context.Background())
	var se *piholeapi.StatusError
	if !errors.As(err, &se) || se.Code != http.StatusInternalServerError {
		t.Fatalf("err = %v, want a 500 StatusError", err)
	}
	if n := len([]rune(se.Message)); n == 0 || n > 301 {
		t.Errorf("message is %d runes, want 1..301", n)
	}
	if piholeapi.Kind(err) != piholeapi.CodeStatusError {
		t.Errorf("Kind = %q", piholeapi.Kind(err))
	}
}

func TestWriteWithEmptyBody(t *testing.T) {
	ph := piholetest.New(t, password)
	ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
		w.WriteHeader(http.StatusCreated)
		return true
	})
	got, err := newClient(t, ph.URL).AddDomain(context.Background(), piholeapi.DomainEntry{Domain: "a.example", Type: "allow", Kind: "exact"})
	if err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if got.Domain != "a.example" || !got.Enabled || got.Groups == nil {
		t.Errorf("returned %+v, want the entry as sent", got)
	}
}

func TestSetBlocking(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		enabled   bool
		timer     time.Duration
		wantTimer string // JSON of the timer sent
		wantErr   bool
	}{
		{name: "enable", enabled: true, wantTimer: "null"},
		{name: "disable", wantTimer: "null"},
		{name: "disable for 5 minutes", timer: 5 * time.Minute, wantTimer: "300"},
		{name: "part seconds round up", timer: 1500 * time.Millisecond, wantTimer: "2"},
		{name: "a day is the most", timer: 24 * time.Hour, wantTimer: "86400"},
		{name: "longer than a day", timer: 24*time.Hour + time.Second, wantErr: true},
		{name: "negative", timer: -time.Second, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			var sent map[string]json.RawMessage
			ph.Handle(func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPost && r.URL.Path == "/api/dns/blocking" {
					b, _ := io.ReadAll(r.Body)
					_ = json.Unmarshal(b, &sent)
					r.Body = io.NopCloser(strings.NewReader(string(b)))
				}
				return false
			})
			st, err := newClient(t, ph.URL).SetBlocking(ctx, tt.enabled, tt.timer)
			if tt.wantErr {
				if !errors.Is(err, piholeapi.ErrInvalidArgument) {
					t.Fatalf("err = %v, want ErrInvalidArgument", err)
				}
				if sent != nil {
					t.Error("an invalid timer reached Pi-hole")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(sent["timer"]) != tt.wantTimer {
				t.Errorf("timer sent %s, want %s", sent["timer"], tt.wantTimer)
			}
			want := map[bool]string{true: piholeapi.BlockingEnabled, false: piholeapi.BlockingDisabled}[tt.enabled]
			if st.Blocking != want {
				t.Errorf("status %q, want %q", st.Blocking, want)
			}
			if (st.Timer != nil) != (tt.timer > 0) {
				t.Errorf("timer in status = %v", st.Timer)
			}
		})
	}
}

// UpdateDomain sends every field, so Pi-hole's PUT can't fall back to enabling a disabled entry.
func TestUpdateDomainKeepsDisabled(t *testing.T) {
	ctx := context.Background()
	ph := piholetest.New(t, password)
	g := ph.AddGroup("kids")
	ph.AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Enabled: false})
	c := newClient(t, ph.URL)

	list, err := c.ListDomains(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListDomains = %v, %v", list, err)
	}
	d := list[0]
	d.Comment, d.Groups = "school nights", []int{g}
	saved, err := c.UpdateDomain(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if saved.DateModified <= d.DateModified {
		t.Errorf("returned entry %+v isn't the one Pi-hole saved", saved)
	}
	got := ph.Domains()[0]
	if got.Enabled || got.Comment != "school nights" || len(got.Groups) != 1 || got.Groups[0] != g {
		t.Errorf("after update: %+v", got)
	}

	if err := c.DeleteDomain(ctx, d.Domain, d.Type, d.Kind); err != nil {
		t.Fatal(err)
	}
	if n := len(ph.Domains()); n != 0 {
		t.Errorf("%d domains left after delete", n)
	}
	var se *piholeapi.StatusError
	if err := c.DeleteDomain(ctx, d.Domain, d.Type, d.Kind); !errors.As(err, &se) || se.Code != http.StatusNotFound {
		t.Errorf("second delete: %v, want a 404 StatusError", err)
	}
}
