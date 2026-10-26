// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package main

// reexecAsService does nothing off Linux: there is no LXC install there.
func reexecAsService(string, []string) error { return nil }
