package web

import (
	"io/fs"
	"testing"
)

// Dist must work whether or not the frontend has been built, and must report
// which case it's in correctly.
func TestDist(t *testing.T) {
	dist, built := Dist()
	_, err := fs.Stat(dist, "index.html")
	if built != (err == nil) {
		t.Fatalf("built=%v but stat(index.html) err=%v", built, err)
	}
}
