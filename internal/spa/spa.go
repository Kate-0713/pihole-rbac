// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package spa serves the built SvelteKit app: its static files, and index.html for any other path, so the app's
// client-side router can handle it. It also works out the CSP hashes of the page's inline scripts, because the page
// SvelteKit generates boots the app from an inline script that script-src 'self' alone would block.
package spa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	// Files under _app/immutable/ have a content hash in their name, so a new build never reuses a name.
	cacheImmutable = "public, max-age=31536000, immutable"
	// Everything else, index.html above all, is checked with the server on every use, so a new build is picked up
	// at once.
	cacheRevalidate = "no-cache"
)

// contentTypes is used instead of mime.TypeByExtension, which on Windows reads the registry and can report a wrong
// type for .js. With X-Content-Type-Options: nosniff, a wrong type stops the browser running the app.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".webmanifest": "application/manifest+json",
	".txt":         "text/plain; charset=utf-8",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".webp":        "image/webp",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
}

func contentType(name string) string {
	if ct, ok := contentTypes[strings.ToLower(path.Ext(name))]; ok {
		return ct
	}
	return "application/octet-stream"
}

// Handler serves a built SPA.
type Handler struct {
	files   fs.FS
	index   []byte
	etag    string
	scripts []string
}

// New reads index.html from the root of files and works out the hashes of its inline scripts.
func New(files fs.FS) (*Handler, error) {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return nil, fmt.Errorf("frontend: %w", err)
	}
	hashes, err := InlineScriptHashes(index)
	if err != nil {
		return nil, fmt.Errorf("frontend: index.html: %w", err)
	}
	sum := sha256.Sum256(index)
	return &Handler{
		files:   files,
		index:   index,
		etag:    `"` + hex.EncodeToString(sum[:16]) + `"`,
		scripts: hashes,
	}, nil
}

// ScriptHashes returns the CSP source expressions ('sha256-…') for the inline scripts in index.html.
func (h *Handler) ScriptHashes() []string {
	return slices.Clone(h.scripts)
}

// ServeHTTP serves the file at the request path if there is one, a 404 for a missing file under _app/ (a stale page
// asking for a chunk from an older build must get an error, not HTML), and index.html for anything else.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
		return
	}
	// Cleaning a rooted path can't climb above the root, so name is always inside files.
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || name == "index.html" {
		h.serveIndex(w, r)
		return
	}
	if served := h.serveFile(w, r, name); served {
		return
	}
	if name == "_app" || strings.HasPrefix(name, "_app/") {
		w.Header().Set("Cache-Control", cacheRevalidate)
		http.Error(w, "Not found.", http.StatusNotFound)
		return
	}
	h.serveIndex(w, r)
}

func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Content-Type", contentTypes[".html"])
	hdr.Set("Cache-Control", cacheRevalidate)
	hdr.Set("ETag", h.etag) // ServeContent answers If-None-Match with 304
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(h.index))
}

// serveFile serves name if it is a regular file, and reports whether it did.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, name string) bool {
	if !fs.ValidPath(name) {
		return false
	}
	f, err := h.files.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	content, ok := f.(io.ReadSeeker)
	if !ok {
		b, err := io.ReadAll(f)
		if err != nil {
			return false
		}
		content = bytes.NewReader(b)
	}
	hdr := w.Header()
	hdr.Set("Content-Type", contentType(name))
	if strings.HasPrefix(name, "_app/immutable/") {
		hdr.Set("Cache-Control", cacheImmutable)
	} else {
		hdr.Set("Cache-Control", cacheRevalidate)
	}
	http.ServeContent(w, r, name, st.ModTime(), content)
	return true
}

// NotBuilt serves a placeholder page for every path, for a binary built without the frontend.
func NotBuilt() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed.", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", contentTypes[".html"])
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, notBuiltPage)
		}
	})
}

const notBuiltPage = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>pihole-rbac: frontend not built</title></head>
<body>
<h1>Frontend not built</h1>
<p>This pihole-rbac binary was built without its web interface. The API is still available under <code>/api/</code>.</p>
<p>Build it with <code>make build</code> (or <code>.\build.ps1 build</code> on Windows), or run <code>npm run dev</code> in <code>web/</code> during development.</p>
</body>
</html>
`

var (
	scriptOpen  = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
	scriptClose = regexp.MustCompile(`(?i)</script\s*>`)
	srcAttr     = regexp.MustCompile(`(?i)(^|\s)src\s*=`)
)

// InlineScriptHashes returns a CSP source expression ('sha256-…') for each distinct inline script in page, in the
// order they appear. Scripts with a src attribute are skipped. It is written for the page SvelteKit generates, not
// arbitrary HTML: it doesn't skip HTML comments, for example.
func InlineScriptHashes(page []byte) ([]string, error) {
	var hashes []string
	for rest := page; ; {
		open := scriptOpen.FindSubmatchIndex(rest)
		if open == nil {
			return hashes, nil
		}
		attrs, body := rest[open[2]:open[3]], rest[open[1]:]
		end := scriptClose.FindIndex(body)
		if end == nil {
			return nil, fmt.Errorf("unterminated <script> element")
		}
		if !srcAttr.Match(attrs) {
			if h := scriptHash(body[:end[0]]); !slices.Contains(hashes, h) {
				hashes = append(hashes, h)
			}
		}
		rest = body[end[1]:]
	}
}

// scriptHash hashes a script's text as the browser does: after the HTML parser has turned every CRLF and lone CR
// into LF. Without that, a page with Windows line endings would get a hash the browser never matches.
func scriptHash(text []byte) string {
	text = bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n"))
	text = bytes.ReplaceAll(text, []byte("\r"), []byte("\n"))
	sum := sha256.Sum256(text)
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}
