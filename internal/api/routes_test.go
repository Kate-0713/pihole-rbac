// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bufio"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// specOp is one operation of api/openapi.yaml as far as access goes.
type specOp struct {
	permission string // the x-permission value, or "" if there is none
	public     bool   // `security: []`
}

var (
	specPathLine   = regexp.MustCompile(`^  (/\S*):\s*$`)
	specMethodLine = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	specPermLine   = regexp.MustCompile(`^      x-permission:\s*(\S+)\s*$`)
)

// readSpecOps reads the operations from the spec, keyed by mux pattern. The spec is regular enough (paths at two
// spaces, methods at four, operation keys at six) that a line scan does the job without a YAML dependency in the
// application's module.
func readSpecOps(t *testing.T) map[string]specOp {
	t.Helper()
	f, err := os.Open("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	ops := map[string]specOp{}
	var path, key string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "components:"):
			return ops
		case specPathLine.MatchString(line):
			path, key = specPathLine.FindStringSubmatch(line)[1], ""
		case specMethodLine.MatchString(line):
			key = strings.ToUpper(specMethodLine.FindStringSubmatch(line)[1]) + " " + path
			ops[key] = specOp{}
		case key != "" && specPermLine.MatchString(line):
			op := ops[key]
			op.permission = specPermLine.FindStringSubmatch(line)[1]
			ops[key] = op
		case key != "" && strings.TrimSpace(line) == "security: []" && strings.HasPrefix(line, "      security"):
			op := ops[key]
			op.public = true
			ops[key] = op
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return ops
}

// TestRoutePermissionsMatchSpec checks routes.go against the spec in both directions: every operation has a table
// entry and every entry has an operation, and what each declares is the same.
func TestRoutePermissionsMatchSpec(t *testing.T) {
	ops := readSpecOps(t)
	if len(ops) == 0 {
		t.Fatal("found no operations in the spec")
	}

	for pattern, op := range ops {
		got, ok := routePermission[pattern]
		if !ok {
			t.Errorf("%s is in the spec but not in routePermission", pattern)
			continue
		}
		want := op.permission
		if op.public {
			if op.permission != "" {
				t.Errorf("%s is public (security: []) but has x-permission %q", pattern, op.permission)
			}
			want = accessPublic
		} else if op.permission == "" {
			t.Errorf("%s needs a session but has no x-permission", pattern)
		}
		if got != want {
			t.Errorf("%s: routePermission has %q, the spec has %q", pattern, got, want)
		}
	}
	for pattern := range routePermission {
		if _, ok := ops[pattern]; !ok {
			t.Errorf("%s is in routePermission but not in the spec", pattern)
		}
	}
}

func TestRoutePermissionValues(t *testing.T) {
	for pattern, v := range routePermission {
		if _, _, ok := parseAccess(v); !ok {
			t.Errorf("%s: %q isn't public, session, a global permission, target:any or target:<non-global permission>", pattern, v)
		}
	}
	tests := []struct {
		v      string
		kind   string
		perm   string
		wantOK bool
	}{
		{"public", "public", "", true},
		{"session", "session", "", true},
		{"config.reload", "global", "config.reload", true},
		{"target:domains.edit", "target", "domains.edit", true},
		{"target:drift.reconcile", "target", "drift.reconcile", true},
		{"target:any", "target", "", true},
		{"domains.edit", "global", "domains.edit", false},          // target-scoped, so it needs the target: prefix
		{"target:config.reload", "target", "config.reload", false}, // global, so the gate checks it
		{"roles.manage|users.manage", "global", "roles.manage|users.manage", true},
		{"roles.manage|roles.manage", "global", "roles.manage|roles.manage", false}, // named twice
		{"roles.manage|domains.view", "global", "roles.manage|domains.view", false}, // not global
		{"roles.manage|", "global", "roles.manage|", false},
		{"nonsense.perm", "global", "nonsense.perm", false},
		{"target:nonsense.perm", "target", "nonsense.perm", false},
		{"", "global", "", false},
	}
	for _, tt := range tests {
		kind, perm, ok := parseAccess(tt.v)
		if kind != tt.kind || perm != tt.perm || ok != tt.wantOK {
			t.Errorf("parseAccess(%q) = %q, %q, %v; want %q, %q, %v", tt.v, kind, perm, ok, tt.kind, tt.perm, tt.wantOK)
		}
	}
}

// TestUndeclaredRouteIsRefused: a route that somehow has no entry fails closed, even for a logged-in admin.
func TestUndeclaredRouteIsRefused(t *testing.T) {
	e := newTestEnv(t)
	e.addUser("admin", "admin-password-1", true)
	c := e.client("10.0.0.1:1")
	c.login("admin", "admin-password-1")

	const pattern = "GET /api/v1/about"
	saved := routePermission[pattern]
	delete(routePermission, pattern)
	defer func() { routePermission[pattern] = saved }()

	if res := c.do(http.MethodGet, "/api/v1/about", nil); res.Code != http.StatusInternalServerError {
		t.Fatalf("undeclared route: status %d, want 500", res.Code)
	}
}
