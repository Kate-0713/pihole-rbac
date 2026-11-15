// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package lists

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCheckAddress(t *testing.T) {
	tests := []struct {
		address   string
		allowFile bool
		want      string // "" for accepted, otherwise the reason
	}{
		{"https://lists.example/ads.txt", false, ""},
		{"http://lists.example/ads.txt", false, ""},
		{"HTTPS://lists.example/ads.txt", false, ""},
		{"https://lists.example/l?key=abc&format=hosts#top", false, ""},
		{"https://lists.example:8443/ads.txt", false, ""},
		{"https://[2001:db8::1]/ads.txt", false, ""},
		{"https://192.168.1.10/ads.txt", false, ""}, // an internal address is allowed: Pi-hole's admin allows it too
		{"https://lists.example/café.txt", false, ""},
		{"https://lists.example/user@example.txt", false, ""}, // an @ in the path isn't a login

		{"", false, ReasonInvalid},
		{"https://lists.example/" + strings.Repeat("a", MaxAddressLength), false, ReasonInvalid},
		{"https://lists.example/a b.txt", false, ReasonInvalid},
		{"https://lists.example/a\tb.txt", false, ReasonInvalid},
		{"https://lists.example/ads.txt\n", false, ReasonInvalid},
		{"https://lists.example/\x00", false, ReasonInvalid},
		{"https://lists.example/ ", false, ReasonInvalid},
		{"https://lists.example/\xff", false, ReasonInvalid},
		{"https:///ads.txt", false, ReasonInvalid},
		{"https://:443/ads.txt", false, ReasonInvalid},
		{"https://lists.example/%zz", false, ReasonInvalid},

		{"https://user:secret@lists.example/ads.txt", false, ReasonCredentials},
		{"https://token@lists.example/ads.txt", false, ReasonCredentials},
		{"https://:secret@lists.example/ads.txt", false, ReasonCredentials},
		{"sftp://user@host/ads.txt", false, ReasonCredentials},

		{"ftp://lists.example/ads.txt", false, ReasonScheme},
		{"ftps://lists.example/ads.txt", false, ReasonScheme},
		{"sftp://host/ads.txt", false, ReasonScheme},
		{"gopher://lists.example/ads.txt", false, ReasonScheme},
		{"lists.example/ads.txt", false, ReasonScheme},
		{"//lists.example/ads.txt", false, ReasonScheme},

		{"file:///etc/pihole/list.txt", false, ReasonFile},
		{"file:/etc/pihole/list.txt", false, ReasonFile},
		{"file:///etc/pihole/list.txt", true, ""},
		{"file:/etc/pihole/list.txt", true, ""},
		{"file://localhost/etc/pihole/list.txt", true, ""},
		{"FILE:///etc/pihole/list.txt", true, ""},
		{"file://otherhost/etc/list.txt", true, ReasonInvalid},
		{"file:relative/list.txt", true, ReasonInvalid},
	}
	for _, tt := range tests {
		err := CheckAddress(tt.address, tt.allowFile)
		var ae *AddressError
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("CheckAddress(%q, %v) = %v, want accepted", tt.address, tt.allowFile, err)
		case tt.want != "" && !errors.As(err, &ae):
			t.Errorf("CheckAddress(%q, %v) = %v, want %s", tt.address, tt.allowFile, err, tt.want)
		case tt.want != "" && ae.Reason != tt.want:
			t.Errorf("CheckAddress(%q, %v) reason %s, want %s (%s)", tt.address, tt.allowFile, ae.Reason, tt.want, ae.Message)
		}
	}
}

func TestCheckAddressMessagesDontEchoTheAddress(t *testing.T) {
	// A refused address can hold a password: the message is shown and may be logged, so it never repeats it.
	err := CheckAddress("https://user:hunter2@lists.example/ads.txt", false)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v", err)
	}
}

func TestRedacted(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"https://lists.example/ads.txt", "https://lists.example/ads.txt"},
		{"https://user:secret@lists.example/ads.txt", "https://xxxxx@lists.example/ads.txt"},
		{"https://token@lists.example/ads.txt", "https://xxxxx@lists.example/ads.txt"},
		{"https://us@er:p@ss@lists.example/a", "https://xxxxx@lists.example/a"}, // the host follows the last @
		{"https://lists.example/user@example.txt", "https://lists.example/user@example.txt"},
		{"https://lists.example/l?u=a@b", "https://lists.example/l?u=a@b"},
		{"https://u:p@lists.example", "https://xxxxx@lists.example"},
		{"https://lists.example/%41?x#y", "https://lists.example/%41?x#y"}, // escaping is left alone
		{"file:///etc/list.txt", "file:///etc/list.txt"},
		{"not a url @ all", "not a url @ all"},
	} {
		if got := Redacted(tt.in); got != tt.want {
			t.Errorf("Redacted(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMarks(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want []string
	}{
		{"https://lists.example/ads.txt", nil},
		{"http://lists.example/ads.txt", nil},
		{"file:///etc/list.txt", []string{MarkFile}},
		{"ftp://lists.example/ads.txt", []string{MarkScheme}},
		{"sftp://user:pw@host/ads.txt", []string{MarkCredentials, MarkScheme}},
		{"https://user:pw@lists.example/ads.txt", []string{MarkCredentials}},
		{"lists.example/ads.txt", []string{MarkScheme}},
	} {
		if got := Marks(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("Marks(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
