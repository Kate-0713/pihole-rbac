// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/minisign"
)

const (
	// Repository is the only place releases come from.
	Repository = "Kate-0713/pihole-rbac"

	// PublicKey is the release signing key: the second line of minisign.pub at the repository root, which a test
	// checks. It is also written into deploy/lxc/install.sh, which the release workflow checks.
	PublicKey = "RWSiTwpzJ1fyeg5FbD9k+fgdn1h28wLmH8lid3NJsRYxw5iv7iHhzUI/"

	// ChecksumsName and SignatureName are the release's signed checksum list and its minisign signature.
	ChecksumsName = "checksums.txt"
	SignatureName = ChecksumsName + ".minisig"

	// BinaryName is the binary inside each archive.
	BinaryName = "pihole-rbac"

	apiBase      = "https://api.github.com"
	downloadBase = "https://github.com"

	// userAgent is required by GitHub's API. It carries no version or anything else about the install.
	userAgent = "pihole-rbac"

	maxMetadata  = 2 << 20   // the release JSON, which includes the changelog
	maxChecksums = 64 << 10  // checksums.txt
	maxArchive   = 128 << 20 // one archive; a real one is about 15 MiB
	maxBinary    = 256 << 20 // the binary inside it, uncompressed
)

var (
	// ErrNoRelease is returned by Latest when the repository has no published release that isn't a prerelease.
	ErrNoRelease = errors.New("no release has been published yet")
	// ErrNotFound is returned when a release or one of its files doesn't exist.
	ErrNotFound = errors.New("not found")
)

// Key returns the built-in release signing key.
func Key() minisign.PublicKey {
	k, err := minisign.ParsePublicKey(PublicKey)
	if err != nil {
		panic("release: built-in public key: " + err.Error())
	}
	return k
}

// TrustedComment is the trusted comment the release workflow signs into a release's checksums. Checking it stops a
// genuine signature for one release from being passed off as another's.
func TrustedComment(v Version) string { return "pihole-rbac " + v.Tag() }

// ArchiveName is a release's archive for linux/arch, as GoReleaser names it: "pihole-rbac_2.1.0_linux_amd64.tar.gz".
func ArchiveName(v Version, arch string) string {
	return fmt.Sprintf("pihole-rbac_%s_linux_%s.tar.gz", v.String(), arch)
}

// SupportedArch reports whether releases are built for a GOARCH.
func SupportedArch(arch string) bool { return arch == "amd64" || arch == "arm64" }

// PageURL is the release's page on GitHub, which has its changelog.
func PageURL(v Version) string {
	return downloadBase + "/" + Repository + "/releases/tag/" + v.Tag()
}

// Release is a published release.
type Release struct {
	Version     Version
	PublishedAt time.Time
}

// Client reads releases from GitHub. Its addresses are fixed; only tests change them.
type Client struct {
	http     *http.Client
	api      string
	download string
	key      minisign.PublicKey
}

// NewClient returns a client for the project's GitHub releases. Each request, including reading the whole response,
// must finish within timeout. Requests go through the proxy named by HTTPS_PROXY, if any.
func NewClient(timeout time.Duration) *Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	c := &Client{
		http: &http.Client{
			Transport: t,
			Timeout:   timeout,
			// Downloads redirect to GitHub's asset host. What arrives is checked against the signature either way,
			// but never follow a redirect from HTTPS to plain HTTP.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
					return fmt.Errorf("refusing a redirect to %s", req.URL.Scheme)
				}
				return nil
			},
		},
		api:      apiBase,
		download: downloadBase,
		key:      Key(),
	}
	testOverride(c)
	return c
}

// Latest returns the newest published release that isn't a prerelease or a draft. It returns ErrNoRelease when
// there isn't one.
func (c *Client) Latest(ctx context.Context) (Release, error) {
	body, err := c.get(ctx, c.api+"/repos/"+Repository+"/releases/latest", maxMetadata, true)
	if errors.Is(err, ErrNotFound) {
		return Release{}, ErrNoRelease
	}
	if err != nil {
		return Release{}, err
	}
	var r struct {
		TagName     string    `json:"tag_name"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return Release{}, fmt.Errorf("reading the latest release: %w", err)
	}
	v, err := ParseTag(r.TagName)
	if err != nil {
		return Release{}, fmt.Errorf("the latest release's tag: %w", err)
	}
	if r.Draft || r.Prerelease || v.IsPrerelease() {
		return Release{}, fmt.Errorf("GitHub's latest release %s is a draft or prerelease", v.Tag())
	}
	return Release{Version: v, PublishedAt: r.PublishedAt}, nil
}

// Checksums maps each file of a release to its SHA-256.
type Checksums map[string][sha256.Size]byte

// Checksums downloads a release's checksum list and its signature, verifies the signature with the built-in key,
// checks that the trusted comment names this release, and returns the list. ErrNotFound means the release (or its
// checksums) doesn't exist; a failed check wraps minisign.ErrInvalid.
func (c *Client) Checksums(ctx context.Context, v Version) (Checksums, error) {
	list, err := c.get(ctx, c.assetURL(v, ChecksumsName), maxChecksums, false)
	if err != nil {
		return nil, fmt.Errorf("downloading %s of %s: %w", ChecksumsName, v.Tag(), err)
	}
	sig, err := c.get(ctx, c.assetURL(v, SignatureName), minisign.MaxSignatureSize, false)
	if err != nil {
		return nil, fmt.Errorf("downloading %s of %s: %w", SignatureName, v.Tag(), err)
	}
	return VerifyChecksums(c.key, v, list, sig)
}

// VerifyChecksums checks a release's checksum list against its signature and the release it should belong to, and
// parses it.
func VerifyChecksums(key minisign.PublicKey, v Version, list, sig []byte) (Checksums, error) {
	trusted, err := minisign.Verify(key, list, sig)
	if err != nil {
		return nil, fmt.Errorf("checking the signature of %s's checksums: %w", v.Tag(), err)
	}
	if trusted != TrustedComment(v) {
		return nil, fmt.Errorf("checking the signature of %s's checksums: %w: it is for %q, not %q",
			v.Tag(), minisign.ErrInvalid, trusted, TrustedComment(v))
	}
	sums := Checksums{}
	sc := bufio.NewScanner(bytes.NewReader(list))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		raw, err := hex.DecodeString(sum)
		if !ok || err != nil || len(raw) != sha256.Size || name == "" || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("%s of %s has a malformed line", ChecksumsName, v.Tag())
		}
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("%s of %s lists %s twice", ChecksumsName, v.Tag(), name)
		}
		sums[name] = [sha256.Size]byte(raw)
	}
	return sums, sc.Err()
}

// Archive downloads the release's archive for linux/arch and checks it against the verified checksums.
func (c *Client) Archive(ctx context.Context, v Version, arch string, sums Checksums) ([]byte, error) {
	if !SupportedArch(arch) {
		return nil, fmt.Errorf("releases aren't built for %s", arch)
	}
	name := ArchiveName(v, arch)
	want, ok := sums[name]
	if !ok {
		return nil, fmt.Errorf("%s isn't in %s's checksums", name, v.Tag())
	}
	b, err := c.get(ctx, c.assetURL(v, name), maxArchive, false)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	if err := CheckSum(b, want); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

// CheckSum compares b's SHA-256 with want.
func CheckSum(b []byte, want [sha256.Size]byte) error {
	got := sha256.Sum256(b)
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		return fmt.Errorf("%w: SHA-256 doesn't match the signed checksum", minisign.ErrInvalid)
	}
	return nil
}

// ExtractBinary returns the pihole-rbac binary from a release archive: a regular file of that name at the top
// level, exactly once.
func ExtractBinary(archive []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("reading the archive: %w", err)
	}
	tr := tar.NewReader(zr)
	var bin []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if strings.TrimPrefix(h.Name, "./") != BinaryName {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("the archive's %s isn't a regular file", BinaryName)
		}
		if bin != nil {
			return nil, fmt.Errorf("the archive holds %s twice", BinaryName)
		}
		if h.Size <= 0 || h.Size > maxBinary {
			return nil, fmt.Errorf("the archive's %s is %d bytes", BinaryName, h.Size)
		}
		bin = make([]byte, h.Size)
		if _, err := io.ReadFull(tr, bin); err != nil {
			return nil, fmt.Errorf("reading %s from the archive: %w", BinaryName, err)
		}
	}
	if bin == nil {
		return nil, fmt.Errorf("the archive has no %s", BinaryName)
	}
	return bin, nil
}

func (c *Client) assetURL(v Version, name string) string {
	return c.download + "/" + Repository + "/releases/download/" + v.Tag() + "/" + name
}

// get fetches url and returns at most max bytes of its body; a longer body is an error. A 404 is ErrNotFound.
func (c *Client) get(ctx context.Context, url string, max int64, api bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
		resp.Header.Get("X-RateLimit-Remaining") == "0":
		return nil, errors.New("GitHub's rate limit for this address is used up; try again later")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("response is over %d bytes", max)
	}
	return b, nil
}
