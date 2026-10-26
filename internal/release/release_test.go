// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/Kate-0713/pihole-rbac/internal/minisign"
)

func TestPublicKeyMatchesRepository(t *testing.T) {
	b, err := os.ReadFile("../../minisign.pub")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(b), "\r\n", "\n")), "\n")
	if len(lines) != 2 || lines[1] != PublicKey {
		t.Fatalf("release.PublicKey doesn't match the second line of minisign.pub:\n%s", b)
	}
	if id := Key().KeyID(); !strings.HasSuffix(lines[0], " "+id) {
		t.Errorf("key ID %s doesn't match minisign.pub's comment %q", id, lines[0])
	}
}

// The checksums of v2.0.0-rc.1 as published, signed by the release workflow.
func TestVerifyChecksumsRelease(t *testing.T) {
	list, err := os.ReadFile("../minisign/testdata/checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("../minisign/testdata/checksums.txt.minisig")
	if err != nil {
		t.Fatal(err)
	}
	rc1, _ := ParseTag("v2.0.0-rc.1")
	sums, err := VerifyChecksums(Key(), rc1, list, sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(sums) != 2 {
		t.Errorf("got %d checksums, want 2", len(sums))
	}
	want, _ := hex.DecodeString("53a144ff623704ac212d01bc0d2429406d5ce0572c600377cfd8e76d3bd2014c")
	if got := sums[ArchiveName(rc1, "amd64")]; !bytes.Equal(got[:], want) {
		t.Errorf("amd64 checksum = %x", got)
	}

	// The same genuine signature presented as another release's.
	other, _ := ParseTag("v2.0.1")
	if _, err := VerifyChecksums(Key(), other, list, sig); !errors.Is(err, minisign.ErrInvalid) ||
		!strings.Contains(err.Error(), `not "pihole-rbac v2.0.1"`) {
		t.Errorf("err = %v, want ErrInvalid naming the trusted comment", err)
	}
}

// fakeRelease is a release signed with a test key, served by a fake GitHub.
type fakeRelease struct {
	t      *testing.T
	key    minisign.PublicKey
	priv   ed25519.PrivateKey
	files  map[string][]byte // download path -> body
	latest string            // the /releases/latest body; "" for 404
	status int               // if set, every request answers this
	header http.Header
}

func newFakeRelease(t *testing.T) *fakeRelease {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte("Ed"), 1, 2, 3, 4, 5, 6, 7, 8), pub...)
	key, err := minisign.ParsePublicKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return &fakeRelease{t: t, key: key, priv: priv, files: map[string][]byte{}}
}

func (f *fakeRelease) signature(msg []byte, trusted string) []byte {
	d := blake2b.Sum512(msg)
	sig := ed25519.Sign(f.priv, d[:])
	line := append(append([]byte("ED"), f.key.ID[:]...), sig...)
	global := ed25519.Sign(f.priv, append(append([]byte{}, sig...), trusted...))
	return []byte("untrusted comment: test\n" + base64.StdEncoding.EncodeToString(line) + "\ntrusted comment: " +
		trusted + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

// publish adds a release with an amd64 archive holding binary, and returns the archive.
func (f *fakeRelease) publish(tag string, binary []byte) []byte {
	v, err := ParseTag(tag)
	if err != nil {
		f.t.Fatal(err)
	}
	archive := tarGz(f.t, map[string][]byte{"LICENCE.md": []byte("licence"), BinaryName: binary})
	name := ArchiveName(v, "amd64")
	sum := sha256.Sum256(archive)
	list := []byte(fmt.Sprintf("%x  %s\n%x  %s\n", sum, name, sha256.Sum256([]byte("arm")), ArchiveName(v, "arm64")))
	prefix := "/" + Repository + "/releases/download/" + tag + "/"
	f.files[prefix+name] = archive
	f.files[prefix+ChecksumsName] = list
	f.files[prefix+SignatureName] = f.signature(list, TrustedComment(v))
	return archive
}

func (f *fakeRelease) client() *Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "pihole-rbac" {
			f.t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		for k, v := range f.header {
			w.Header()[k] = v
		}
		if f.status != 0 {
			w.WriteHeader(f.status)
			return
		}
		if r.URL.Path == "/api/repos/"+Repository+"/releases/latest" {
			if r.Header.Get("Accept") != "application/vnd.github+json" {
				f.t.Errorf("Accept = %q", r.Header.Get("Accept"))
			}
			if f.latest == "" {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(f.latest))
			return
		}
		if b, ok := f.files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	f.t.Cleanup(srv.Close)
	c := NewClient(5 * time.Second)
	c.api, c.download, c.key = srv.URL+"/api", srv.URL, f.key
	return c
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestLatest(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		status  int
		header  http.Header
		want    string
		wantErr string
	}{
		{name: "release", latest: `{"tag_name":"v2.1.0","draft":false,"prerelease":false,"published_at":"2026-11-01T10:00:00Z"}`, want: "v2.1.0"},
		{name: "none yet", wantErr: ErrNoRelease.Error()},
		{name: "prerelease flag", latest: `{"tag_name":"v2.1.0","prerelease":true}`, wantErr: "draft or prerelease"},
		{name: "prerelease tag", latest: `{"tag_name":"v2.1.0-rc.1"}`, wantErr: "draft or prerelease"},
		{name: "draft", latest: `{"tag_name":"v2.1.0","draft":true}`, wantErr: "draft or prerelease"},
		{name: "bad tag", latest: `{"tag_name":"v2.1.0/../../evil"}`, wantErr: "not a version"},
		{name: "not JSON", latest: `<html>`, wantErr: "reading the latest release"},
		{name: "rate limited", status: http.StatusForbidden, header: http.Header{"X-Ratelimit-Remaining": {"0"}}, wantErr: "rate limit"},
		{name: "server error", status: http.StatusBadGateway, wantErr: "502"},
		{name: "oversized", latest: `{"tag_name":"v2.1.0","body":"` + strings.Repeat("a", maxMetadata) + `"}`, wantErr: "over"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeRelease(t)
			f.latest, f.status, f.header = tt.latest, tt.status, tt.header
			r, err := f.client().Latest(context.Background())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Version.Tag() != tt.want || r.PublishedAt.IsZero() {
				t.Errorf("got %+v", r)
			}
		})
	}
}

func TestChecksumsAndArchive(t *testing.T) {
	f := newFakeRelease(t)
	binary := []byte("#!new binary")
	f.publish("v2.1.0", binary)
	c := f.client()
	v, _ := ParseTag("v2.1.0")
	ctx := context.Background()

	sums, err := c.Checksums(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := c.Archive(ctx, v, "amd64", sums)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ExtractBinary(archive)
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("ExtractBinary = %q, %v", got, err)
	}

	t.Run("no such release", func(t *testing.T) {
		missing, _ := ParseTag("v9.9.9")
		if _, err := c.Checksums(ctx, missing); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("archive not in checksums", func(t *testing.T) {
		if _, err := c.Archive(ctx, v, "amd64", Checksums{}); err == nil || !strings.Contains(err.Error(), "isn't in") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("unsupported arch", func(t *testing.T) {
		if _, err := c.Archive(ctx, v, "riscv64", sums); err == nil {
			t.Error("riscv64 accepted")
		}
	})
	t.Run("archive replaced", func(t *testing.T) {
		path := "/" + Repository + "/releases/download/v2.1.0/" + ArchiveName(v, "amd64")
		f.files[path] = tarGz(t, map[string][]byte{BinaryName: []byte("#!evil")})
		if _, err := c.Archive(ctx, v, "amd64", sums); !errors.Is(err, minisign.ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("checksums replaced", func(t *testing.T) {
		path := "/" + Repository + "/releases/download/v2.1.0/" + ChecksumsName
		f.files[path] = append(bytes.Clone(f.files[path]), "00  extra\n"...)
		if _, err := c.Checksums(ctx, v); !errors.Is(err, minisign.ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
	t.Run("an older release's signed files under a new tag", func(t *testing.T) {
		f.publish("v2.0.0", binary)
		old := "/" + Repository + "/releases/download/v2.0.0/"
		now := "/" + Repository + "/releases/download/v2.2.0/"
		f.files[now+ChecksumsName] = f.files[old+ChecksumsName]
		f.files[now+SignatureName] = f.files[old+SignatureName]
		v22, _ := ParseTag("v2.2.0")
		if _, err := c.Checksums(ctx, v22); !errors.Is(err, minisign.ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
}

func TestVerifyChecksumsMalformed(t *testing.T) {
	f := newFakeRelease(t)
	v, _ := ParseTag("v2.1.0")
	good := strings.Repeat("ab", 32)
	tests := []struct{ name, list, wantErr string }{
		{"ok with blank line", good + "  a.tar.gz\n\n", ""},
		{"one space", good + " a.tar.gz\n", "malformed"},
		{"short hash", "abcd  a.tar.gz\n", "malformed"},
		{"not hex", strings.Repeat("zz", 32) + "  a.tar.gz\n", "malformed"},
		{"path", good + "  ../a.tar.gz\n", "malformed"},
		{"duplicate", good + "  a.tar.gz\n" + good + "  a.tar.gz\n", "twice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := f.signature([]byte(tt.list), TrustedComment(v))
			_, err := VerifyChecksums(f.key, v, []byte(tt.list), sig)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestExtractBinary(t *testing.T) {
	entry := func(name string, typ byte, body string) func(*tar.Writer) {
		return func(tw *tar.Writer) {
			h := &tar.Header{Name: name, Mode: 0o755, Typeflag: typ, Size: int64(len(body))}
			if typ == tar.TypeSymlink {
				h.Linkname, h.Size = "/bin/sh", 0
			}
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			_, _ = tw.Write([]byte(body))
		}
	}
	build := func(entries ...func(*tar.Writer)) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		for _, e := range entries {
			e(tw)
		}
		_ = tw.Close()
		_ = zw.Close()
		return buf.Bytes()
	}
	tests := []struct {
		name    string
		archive []byte
		want    string
		wantErr string
	}{
		{"top level", build(entry("README.md", tar.TypeReg, "r"), entry("pihole-rbac", tar.TypeReg, "bin")), "bin", ""},
		{"dot slash", build(entry("./pihole-rbac", tar.TypeReg, "bin")), "bin", ""},
		{"missing", build(entry("README.md", tar.TypeReg, "r")), "", "has no"},
		{"nested only", build(entry("x/pihole-rbac", tar.TypeReg, "bin")), "", "has no"},
		{"twice", build(entry("pihole-rbac", tar.TypeReg, "a"), entry("./pihole-rbac", tar.TypeReg, "b")), "", "twice"},
		{"symlink", build(entry("pihole-rbac", tar.TypeSymlink, "")), "", "regular file"},
		{"empty", build(entry("pihole-rbac", tar.TypeReg, "")), "", "0 bytes"},
		{"not gzip", []byte("plain"), "", "reading the archive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractBinary(tt.archive)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestRedirects(t *testing.T) {
	check := NewClient(time.Second).http.CheckRedirect
	req := func(u string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, u, nil)
		return r
	}
	https := req("https://github.com/x")
	if err := check(req("https://release-assets.githubusercontent.com/x"), []*http.Request{https}); err != nil {
		t.Errorf("https redirect refused: %v", err)
	}
	if err := check(req("http://release-assets.githubusercontent.com/x"), []*http.Request{https}); err == nil {
		t.Error("redirect from https to http was allowed")
	}
	if err := check(req("https://x/"), []*http.Request{https, https, https, https, https}); err == nil {
		t.Error("a sixth redirect was allowed")
	}
}

func TestNames(t *testing.T) {
	v, _ := ParseTag("v2.0.0-rc.1")
	if got := ArchiveName(v, "arm64"); got != "pihole-rbac_2.0.0-rc.1_linux_arm64.tar.gz" {
		t.Errorf("ArchiveName = %s", got)
	}
	if got := PageURL(v); got != "https://github.com/Kate-0713/pihole-rbac/releases/tag/v2.0.0-rc.1" {
		t.Errorf("PageURL = %s", got)
	}
	if got := TrustedComment(v); got != "pihole-rbac v2.0.0-rc.1" {
		t.Errorf("TrustedComment = %s", got)
	}
}
