// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build updatertest

package release

import (
	"os"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/minisign"
)

// testOverride lets the end-to-end update test in deploy/lxc/test-install.sh serve releases from a local server signed
// with a throwaway key. It exists only in binaries built with -tags updatertest, which the release workflow never
// builds; such a binary says so in `pihole-rbac version`.
//
//	PIHOLE_RBAC_TEST_RELEASES_URL  serves <url>/api/repos/<repo>/releases/latest and <url>/<repo>/releases/download/...
//	PIHOLE_RBAC_TEST_RELEASE_KEY   the throwaway minisign public key (the base64 line)
func testOverride(c *Client) {
	url := strings.TrimRight(os.Getenv("PIHOLE_RBAC_TEST_RELEASES_URL"), "/")
	key := os.Getenv("PIHOLE_RBAC_TEST_RELEASE_KEY")
	if url == "" || key == "" {
		return
	}
	k, err := minisign.ParsePublicKey(key)
	if err != nil {
		panic("PIHOLE_RBAC_TEST_RELEASE_KEY: " + err.Error())
	}
	c.api, c.download, c.key = url+"/api", url, k
}

// TestBuild reports whether this binary was built with the updatertest tag.
const TestBuild = true
