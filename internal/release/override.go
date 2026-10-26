// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !updatertest

package release

// testOverride does nothing in a normal build: releases come only from the fixed repository, checked with the
// built-in key. See override_updatertest.go.
func testOverride(*Client) {}

// TestBuild reports whether this binary was built with the updatertest tag.
const TestBuild = false
