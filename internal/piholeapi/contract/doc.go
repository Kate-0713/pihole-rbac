// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contract holds the contract tests for the Pi-hole client: what the app relies on Pi-hole's v6 API to do,
// written once and run against two backends.
//
// By default the tests run against the fake Pi-hole (piholetest), as part of go test ./... on every platform. With
// PIHOLE_RBAC_TEST_PIHOLE set to a Pi-hole's base URL, the same tests run against that Pi-hole instead, which is
// what the pihole CI job does with a Pi-hole container. If both pass, the fake matches FTL wherever the app depends on
// it; when FTL changes, the real run fails and the fake is corrected along with the code.
//
// The real run changes the Pi-hole freely, deleting its Default group among other things, so it must only ever be
// pointed at a throwaway Pi-hole. It refuses one that holds domains, clients, groups or lists it didn't make. See
// run-pihole.sh for how CI starts one, and the variables it needs.
//
// The package has no code of its own apart from this comment: the tests are its contents.
package contract
