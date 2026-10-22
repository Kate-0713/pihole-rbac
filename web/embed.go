// Package web embeds the built SvelteKit SPA.
//
// adapter-static writes to web/build/app. web/build/.keep is committed so the
// embed pattern always matches something, which keeps `go build`, `go run`
// and `go test ./...` working on a fresh clone before `npm run build`.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:build
var build embed.FS

// Dist returns the built frontend rooted at its index.html, and whether a
// build is actually present. When built is false the FS is empty and the
// server should show a "frontend not built" page instead.
func Dist() (dist fs.FS, built bool) {
	sub, err := fs.Sub(build, "build/app")
	if err != nil {
		// Only possible for an invalid path; "build/app" is a constant.
		panic(err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return sub, false
	}
	return sub, true
}
