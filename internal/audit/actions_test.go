// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Every Action constant in audit.go is in Actions, once, except instance_test; and nothing else is.
func TestActionsListed(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "audit.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]bool{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, spec := range g.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "Action") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					continue
				}
				v, _ := strconv.Unquote(lit.Value)
				consts[v] = true
			}
		}
	}
	delete(consts, ActionInstanceTest)
	listed := map[string]bool{}
	for _, a := range Actions() {
		if listed[a.Name] {
			t.Errorf("%s is listed twice", a.Name)
		}
		listed[a.Name] = true
		if !consts[a.Name] {
			t.Errorf("%s is listed but isn't an action constant", a.Name)
		}
		if a.Group == "" || a.Description == "" {
			t.Errorf("%s has no group or description", a.Name)
		}
	}
	for c := range consts {
		if !listed[c] {
			t.Errorf("action %s isn't in Actions", c)
		}
	}
	if len(consts) < 40 {
		t.Errorf("only %d constants found: the parse is wrong", len(consts))
	}
}
