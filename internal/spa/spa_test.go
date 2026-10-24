// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package spa

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Kate-0713/pihole-rbac/web"
)

// sha is computed independently of scriptHash, so the tests don't just check the code against itself.
func sha(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func TestInlineScriptHashes(t *testing.T) {
	boot := "\n\t\t\t\t{ kit.start(); }\n\t\t\t"
	tests := []struct {
		name    string
		page    string
		want    []string
		wantErr bool
	}{
		{"no scripts", `<html><body><p>hi</p></body></html>`, nil, false},
		{"inline script", `<body><script>` + boot + `</script></body>`, []string{sha(boot)}, false},
		{"external script skipped", `<script src="/a.js"></script><script type="module" src='/b.js'></script>`, nil, false},
		{"data-src is not src", `<script data-src="x">a()</script>`, []string{sha("a()")}, false},
		{"upper case tags", `<SCRIPT>a()</SCRIPT >`, []string{sha("a()")}, false},
		{"CRLF hashed as LF", "<script>a();\r\nb();\rc();</script>", []string{sha("a();\nb();\nc();")}, false},
		{"duplicates once, order kept", `<script>b()</script><script>a()</script><script>b()</script>`,
			[]string{sha("b()"), sha("a()")}, false},
		{"empty script", `<script></script>`, []string{sha("")}, false},
		{"unterminated", `<script>a()`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InlineScriptHashes([]byte(tt.page))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

const testIndex = `<!doctype html><html><head></head><body><div style="display: contents"><script>boot()</script></div></body></html>`

func testFiles() fstest.MapFS {
	return fstest.MapFS{
		"index.html":                       {Data: []byte(testIndex)},
		"robots.txt":                       {Data: []byte("User-agent: *\nDisallow: /\n")},
		"_app/version.json":                {Data: []byte(`{"version":"1"}`)},
		"_app/immutable/entry/start.A1.js": {Data: []byte("export const x = 1;")},
		"_app/immutable/assets/0.B2.css":   {Data: []byte("body{}")},
		"_app/immutable/x.unknownext":      {Data: []byte("?")},
	}
}

func TestNew(t *testing.T) {
	h, err := New(testFiles())
	if err != nil {
		t.Fatal(err)
	}
	if got := h.ScriptHashes(); !slices.Equal(got, []string{sha("boot()")}) {
		t.Fatalf("ScriptHashes = %q", got)
	}
	if _, err := New(fstest.MapFS{}); err == nil {
		t.Fatal("New without index.html succeeded")
	}
	if _, err := New(fstest.MapFS{"index.html": {Data: []byte("<script>x")}}); err == nil {
		t.Fatal("New with an unterminated script succeeded")
	}
}

func TestServeHTTP(t *testing.T) {
	h, err := New(testFiles())
	if err != nil {
		t.Fatal(err)
	}
	const (
		html = "text/html; charset=utf-8"
		js   = "text/javascript; charset=utf-8"
	)
	tests := []struct {
		method, path string
		wantCode     int
		wantType     string
		wantCache    string
		wantBody     string // prefix; "" checks nothing
	}{
		{"GET", "/", 200, html, "no-cache", "<!doctype html>"},
		{"GET", "/index.html", 200, html, "no-cache", "<!doctype html>"},
		{"GET", "/domains?target=i-1", 200, html, "no-cache", "<!doctype html>"},
		{"GET", "/admin/users/3", 200, html, "no-cache", "<!doctype html>"},
		{"GET", "/../../etc/passwd", 200, html, "no-cache", "<!doctype html>"},
		{"GET", "/robots.txt", 200, "text/plain; charset=utf-8", "no-cache", "User-agent"},
		{"GET", "/_app/version.json", 200, "application/json", "no-cache", `{"version"`},
		{"GET", "/_app/immutable/entry/start.A1.js", 200, js, "public, max-age=31536000, immutable", "export"},
		{"GET", "/_app/immutable/assets/0.B2.css", 200, "text/css; charset=utf-8", "public, max-age=31536000, immutable", "body"},
		{"GET", "/_app/immutable/x.unknownext", 200, "application/octet-stream", "public, max-age=31536000, immutable", "?"},
		{"GET", "/_app/immutable/entry/start.OLD.js", 404, "text/plain; charset=utf-8", "no-cache", "Not found."},
		{"GET", "/_app", 404, "text/plain; charset=utf-8", "no-cache", ""},
		{"GET", "/_app/immutable/", 404, "text/plain; charset=utf-8", "no-cache", ""},
		{"HEAD", "/", 200, html, "no-cache", ""},
		{"POST", "/", 405, "text/plain; charset=utf-8", "", ""},
		{"DELETE", "/robots.txt", 405, "text/plain; charset=utf-8", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if got := w.Header().Get("Content-Type"); got != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", got, tt.wantType)
			}
			if got := w.Header().Get("Cache-Control"); got != tt.wantCache {
				t.Errorf("Cache-Control = %q, want %q", got, tt.wantCache)
			}
			if !strings.HasPrefix(w.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want prefix %q", w.Body.String(), tt.wantBody)
			}
			if tt.method == "HEAD" && w.Body.Len() != 0 {
				t.Error("HEAD response has a body")
			}
			if tt.wantCode == 405 && w.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("Allow = %q", w.Header().Get("Allow"))
			}
		})
	}
}

func TestIndexRevalidation(t *testing.T) {
	h, err := New(testFiles())
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on index.html")
	}
	r := httptest.NewRequest("GET", "/some/route", nil)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", w.Code)
	}
}

func TestNotBuilt(t *testing.T) {
	h := NotBuilt()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/login", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "Frontend not built") {
		t.Fatalf("got %d %q", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

// The real build must load, and its bootstrap script must be the one inline script found.
func TestEmbeddedBuild(t *testing.T) {
	dist, built := web.Dist()
	if !built {
		t.Skip("frontend not built")
	}
	h, err := New(dist)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(h.ScriptHashes()); n != 1 {
		t.Fatalf("found %d inline scripts in the built index.html, want 1 (the SvelteKit bootstrap)", n)
	}
}
