// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
)

const adsList = "https://lists.example/ads.txt"

// TestListWrites covers adding, changing and deleting subscribed lists against the fake, which answers as FTL does:
// every write names the type in the query, a PUT is an upsert that clears a comment left out, an address already on
// that type is refused, and deleting a missing list is a 404.
func TestListWrites(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		call  func(c *piholeapi.Client, kids int) error
		sent  string // the request the call makes, as Requests reports it (path only)
		check func(t *testing.T, ph *piholetest.Server, kids int, err error)
	}{
		{
			name: "add sends the type and returns the list as saved",
			call: func(c *piholeapi.Client, kids int) error {
				l, err := c.AddList(ctx, piholeapi.ListEntry{
					Address: "https://lists.example/new.txt", Type: "allow", Comment: "work", Groups: []int{kids}, Enabled: false,
				})
				if err == nil && (l.ID == 0 || l.Type != "allow" || l.Enabled || !slices.Equal(l.Groups, []int{kids})) {
					t.Errorf("saved list %+v", l)
				}
				return err
			},
			sent: "POST /api/lists",
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				l := list(t, ph, "https://lists.example/new.txt", "allow")
				if l.Comment != "work" || l.Enabled || !slices.Equal(l.Groups, []int{kids}) {
					t.Errorf("list %+v", l)
				}
			},
		},
		{
			name: "the same address can be both types",
			call: func(c *piholeapi.Client, _ int) error {
				_, err := c.AddList(ctx, piholeapi.ListEntry{Address: adsList, Type: "allow", Enabled: true})
				return err
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				list(t, ph, adsList, "block")
				list(t, ph, adsList, "allow")
			},
		},
		{
			name: "an address already on that type is rejected",
			call: func(c *piholeapi.Client, _ int) error {
				_, err := c.AddList(ctx, piholeapi.ListEntry{Address: adsList, Type: "block", Enabled: true})
				return err
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if !errors.Is(err, piholeapi.ErrRejected) {
					t.Errorf("err = %v, want ErrRejected", err)
				}
				if n := len(ph.Lists()); n != 1 {
					t.Errorf("%d lists", n)
				}
			},
		},
		{
			name: "update keeps the ID and sets the comment, groups and enabled flag",
			call: func(c *piholeapi.Client, kids int) error {
				_, err := c.UpdateList(ctx, piholeapi.ListEntry{Address: adsList, Type: "block", Comment: "kids only", Groups: []int{kids}})
				return err
			},
			sent: "PUT /api/lists/https:%2F%2Flists.example%2Fads.txt",
			check: func(t *testing.T, ph *piholetest.Server, kids int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				l := list(t, ph, adsList, "block")
				if l.ID != 1+kids || l.Comment != "kids only" || l.Enabled || !slices.Equal(l.Groups, []int{kids}) {
					t.Errorf("list %+v", l)
				}
				if l.DateModified == l.DateAdded {
					t.Error("a comment and enabled change didn't move date_modified")
				}
			},
		},
		{
			name: "a group change alone doesn't move date_modified, as in Pi-hole",
			call: func(c *piholeapi.Client, kids int) error {
				_, err := c.UpdateList(ctx, piholeapi.ListEntry{Address: adsList, Type: "block", Groups: []int{kids}, Enabled: true})
				return err
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if l := list(t, ph, adsList, "block"); err != nil || l.DateModified != l.DateAdded {
					t.Errorf("err = %v, list %+v", err, l)
				}
			},
		},
		{
			name: "an address with a query string and odd characters is escaped in the path",
			call: func(c *piholeapi.Client, _ int) error {
				const odd = "https://lists.example/l?key=a%2Fb&x=café#frag"
				if _, err := c.AddList(ctx, piholeapi.ListEntry{Address: odd, Type: "block", Enabled: true}); err != nil {
					return err
				}
				if _, err := c.UpdateList(ctx, piholeapi.ListEntry{Address: odd, Type: "block", Comment: "odd"}); err != nil {
					return err
				}
				return c.DeleteList(ctx, odd, "block")
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if err != nil {
					t.Fatal(err)
				}
				if n := len(ph.Lists()); n != 1 {
					t.Errorf("%d lists: the odd address was created again by the PUT, or not deleted", n)
				}
			},
		},
		{
			name: "delete",
			call: func(c *piholeapi.Client, _ int) error { return c.DeleteList(ctx, adsList, "block") },
			sent: "DELETE /api/lists/https:%2F%2Flists.example%2Fads.txt",
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				if err != nil || len(ph.Lists()) != 0 {
					t.Errorf("err = %v, lists %+v", err, ph.Lists())
				}
			},
		},
		{
			name: "deleting a list of the other type is a 404",
			call: func(c *piholeapi.Client, _ int) error { return c.DeleteList(ctx, adsList, "allow") },
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				var se *piholeapi.StatusError
				if !errors.As(err, &se) || se.Code != http.StatusNotFound {
					t.Errorf("err = %v, want a 404", err)
				}
				if len(ph.Lists()) != 1 {
					t.Error("the block list was deleted")
				}
			},
		},
		{
			name: "a bad type is refused before anything is sent",
			call: func(c *piholeapi.Client, _ int) error {
				_, err1 := c.AddList(ctx, piholeapi.ListEntry{Address: adsList, Type: "deny"})
				_, err2 := c.UpdateList(ctx, piholeapi.ListEntry{Address: adsList, Type: ""})
				err3 := c.DeleteList(ctx, adsList, "block&type=allow")
				return errors.Join(err1, err2, err3)
			},
			check: func(t *testing.T, ph *piholetest.Server, _ int, err error) {
				for _, e := range err.(interface{ Unwrap() []error }).Unwrap() {
					if !errors.Is(e, piholeapi.ErrInvalidArgument) {
						t.Errorf("err = %v, want ErrInvalidArgument", e)
					}
				}
				for _, r := range ph.Requests() {
					if strings.Contains(r, "/api/lists") {
						t.Errorf("sent %s", r)
					}
				}
			},
		},
		{
			name: "lists are read with their download status",
			call: func(c *piholeapi.Client, _ int) error {
				lists, err := c.ListLists(ctx)
				if err != nil {
					return err
				}
				l := lists[0]
				if l.Status != piholeapi.ListStatusCached || l.Number != 5000 || l.DateUpdated != 1_789_000_000 || l.InvalidDomains != 3 {
					t.Errorf("list %+v", l)
				}
				return nil
			},
			sent: "GET /api/lists",
			check: func(t *testing.T, _ *piholetest.Server, _ int, err error) {
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			kids := ph.AddGroup("kids")
			ph.AddList(piholetest.List{
				Address: adsList, Type: "block", Enabled: true,
				DateUpdated: 1_789_000_000, Number: 5000, InvalidDomains: 3, Status: piholeapi.ListStatusCached,
			})
			ph.Advance(60)
			c := newClient(t, ph.URL)
			err := tt.call(c, kids)
			if tt.sent != "" {
				if reqs := ph.Requests(); !slices.Contains(reqs, tt.sent) {
					t.Errorf("requests %v, want %q", reqs, tt.sent)
				}
			}
			tt.check(t, ph, kids, err)
		})
	}
}

// TestRunGravity: the output is passed on line by line as it arrives, and the outcome comes from the stream, since
// FTL answers 200 before the run: a "Gravity failed" line or a cut-off stream is a failure, and a second run while
// one is going is Pi-hole's 409.
func TestRunGravity(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		run       piholetest.GravityRun
		wantErr   error
		wantKind  string
		wantLines []string
	}{
		{
			name:      "success",
			run:       piholetest.GravityRun{Lines: []string{"  [i] one", "  [i] two\r\x1b[K  [✓] two"}},
			wantLines: []string{"  [i] one", "  [✓] two"},
		},
		{
			name:      "reported failure",
			run:       piholetest.GravityRun{Lines: []string{"  [✗] Unable to connect"}, Fail: true},
			wantErr:   piholeapi.ErrGravityFailed,
			wantKind:  piholeapi.CodeGravityFailed,
			wantLines: []string{"  [✗] Unable to connect", "Gravity failed"},
		},
		{
			name:      "output cut short",
			run:       piholetest.GravityRun{Lines: []string{"  [i] one"}, CutShort: true},
			wantErr:   piholeapi.ErrGravityFailed,
			wantKind:  piholeapi.CodeGravityFailed,
			wantLines: []string{"  [i] one"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := piholetest.New(t, password)
			ph.AddList(piholetest.List{Address: adsList, Type: "block", Enabled: true})
			ph.SetGravity(tt.run)
			c := newClient(t, ph.URL)
			var got []string
			err := c.RunGravity(ctx, func(l string) { got = append(got, l) })
			if !errors.Is(err, tt.wantErr) || (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if k := piholeapi.Kind(err); k != tt.wantKind {
				t.Errorf("Kind = %q, want %q", k, tt.wantKind)
			}
			if !slices.Equal(got, tt.wantLines) {
				t.Errorf("lines %q, want %q", got, tt.wantLines)
			}
			if !slices.Contains(ph.Requests(), "POST /api/action/gravity") {
				t.Errorf("requests %v", ph.Requests())
			}
		})
	}

	t.Run("the summary reports the new count and time", func(t *testing.T) {
		ph := piholetest.New(t, password)
		ph.AddList(piholetest.List{Address: adsList, Type: "block", Enabled: true})
		ph.SetGravityState(0, 0)
		c := newClient(t, ph.URL)
		if err := c.RunGravity(ctx, func(string) {}); err != nil {
			t.Fatal(err)
		}
		sum, err := c.GetLiveSummary(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sum.Gravity.DomainsBeingBlocked != 1000 || sum.Gravity.LastUpdate == 0 {
			t.Errorf("gravity %+v", sum.Gravity)
		}
		if l := ph.Lists()[0]; l.Status != piholeapi.ListStatusUpdated || l.DateUpdated != sum.Gravity.LastUpdate {
			t.Errorf("list after the run %+v", l)
		}
	})

	t.Run("a second run while one is going is gravity_running", func(t *testing.T) {
		ph := piholetest.New(t, password)
		hold := make(chan struct{})
		ph.SetGravity(piholetest.GravityRun{Hold: hold})
		c := newClient(t, ph.URL)
		started := make(chan struct{})
		var once sync.Once
		var first error
		done := make(chan struct{})
		go func() {
			defer close(done)
			first = c.RunGravity(ctx, func(string) { once.Do(func() { close(started) }) })
		}()
		<-started
		err := c.RunGravity(ctx, func(string) { t.Error("the refused run passed on output") })
		if !errors.Is(err, piholeapi.ErrGravityRunning) || piholeapi.Kind(err) != piholeapi.CodeGravityRunning {
			t.Errorf("err = %v, want ErrGravityRunning", err)
		}
		close(hold)
		<-done
		if first != nil {
			t.Errorf("first run: %v", first)
		}
		if n := ph.GravityRuns(); n != 1 {
			t.Errorf("%d runs started, want 1", n)
		}
	})

	t.Run("a cancelled context returns its error", func(t *testing.T) {
		ph := piholetest.New(t, password)
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		ph.SetGravity(piholetest.GravityRun{Hold: hold})
		c := newClient(t, ph.URL)
		cctx, cancel := context.WithCancel(ctx)
		err := c.RunGravity(cctx, func(string) { cancel() })
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("the gravity timeout is separate from the default", func(t *testing.T) {
		ph := piholetest.New(t, password)
		hold := make(chan struct{})
		t.Cleanup(func() { close(hold) })
		ph.SetGravity(piholetest.GravityRun{Hold: hold})
		c := newClient(t, ph.URL, func(o *piholeapi.Options) {
			o.Timeout = 50 * time.Millisecond // would cut every run short if it applied
			o.GravityTimeout = 400 * time.Millisecond
		})
		start := time.Now()
		err := c.RunGravity(ctx, func(string) {})
		if !errors.Is(err, piholeapi.ErrGravityFailed) {
			t.Errorf("err = %v, want ErrGravityFailed after the gravity timeout", err)
		}
		if d := time.Since(start); d < 350*time.Millisecond {
			t.Errorf("gave up after %v: the default timeout was used", d)
		}
	})
}

func list(t *testing.T, ph *piholetest.Server, address, listType string) piholetest.List {
	t.Helper()
	lists := ph.Lists()
	i := slices.IndexFunc(lists, func(l piholetest.List) bool { return l.Address == address && l.Type == listType })
	if i < 0 {
		t.Fatalf("no %s list %q in %+v", listType, address, lists)
	}
	return lists[i]
}
