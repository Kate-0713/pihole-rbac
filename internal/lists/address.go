// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lists holds the app's rules for the addresses of subscribed lists (adlists): which addresses may be added,
// how an address holding a password is shown, and how existing lists the rules wouldn't accept are marked.
//
// Pi-hole itself only refuses whitespace in an address. Its gravity script downloads http, https, ftp, ftps and sftp
// addresses with curl and reads file: paths on the Pi-hole's own host, so the app is stricter: anyone with lists.edit
// can make a Pi-hole fetch an address, and the address is shown to everyone with lists.view and written to the audit
// log.
package lists

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxAddressLength caps an address, in bytes.
const MaxAddressLength = 2048

// Reasons an address is refused, as AddressError.Reason.
const (
	ReasonInvalid     = "invalid"     // empty, too long, whitespace or control characters, or not a URL with a host
	ReasonScheme      = "scheme"      // a scheme other than http, https or file
	ReasonFile        = "file"        // a file: address while allow_file_lists is off
	ReasonCredentials = "credentials" // a user name or password in the address
)

// AddressError is an address the app won't add. Message is a sentence without its full stop, fit to show to the
// person who sent it; it never repeats the address, which may hold a password.
type AddressError struct {
	Reason  string
	Message string
}

func (e *AddressError) Error() string { return "list address: " + e.Message }

func refuse(reason, format string, args ...any) error {
	return &AddressError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// CheckAddress reports whether a list may be added with address: an http or https URL with a host and no user name or
// password, or, only when allowFile is true, a file: URL with an absolute path. It applies to new lists (and lists
// added to another Pi-hole by reconcile), never to lists that already exist.
func CheckAddress(address string, allowFile bool) error {
	switch {
	case address == "":
		return refuse(ReasonInvalid, "The address is empty")
	case len(address) > MaxAddressLength:
		return refuse(ReasonInvalid, "The address is longer than %d characters", MaxAddressLength)
	case !utf8.ValidString(address):
		return refuse(ReasonInvalid, "The address isn't valid UTF-8")
	case strings.IndexFunc(address, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
		return refuse(ReasonInvalid, "The address has spaces or control characters in it")
	}
	if hasUserInfo(address) {
		return refuse(ReasonCredentials, "The address has a user name or password in it, which would be shown to everyone who can see the lists")
	}
	u, err := url.Parse(address)
	if err != nil {
		return refuse(ReasonInvalid, "The address isn't a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" || u.Hostname() == "" {
			return refuse(ReasonInvalid, "The address has no host")
		}
		return nil
	case "file":
		if !allowFile {
			return refuse(ReasonFile, "file: lists aren't allowed (an administrator can allow them in the general settings)")
		}
		if (u.Host != "" && u.Host != "localhost") || !strings.HasPrefix(u.Path, "/") {
			return refuse(ReasonInvalid, "a file: address needs an absolute path on the Pi-hole, like file:///etc/pihole/list.txt")
		}
		return nil
	case "":
		return refuse(ReasonScheme, "The address needs to start with http:// or https://")
	default:
		return refuse(ReasonScheme, "%s: addresses aren't allowed, only http and https", strings.ToLower(u.Scheme))
	}
}

// authority returns where the authority of address starts and ends, or ok false if it has none ("scheme://" followed
// by everything up to the next "/", "?" or "#").
func authority(address string) (start, end int, ok bool) {
	i := strings.Index(address, "://")
	if i <= 0 {
		return 0, 0, false
	}
	start = i + 3
	end = len(address)
	if j := strings.IndexAny(address[start:], "/?#"); j >= 0 {
		end = start + j
	}
	return start, end, true
}

// hasUserInfo reports whether address has a user name or password before its host.
func hasUserInfo(address string) bool {
	start, end, ok := authority(address)
	return ok && strings.Contains(address[start:end], "@")
}

// Redacted is how the app shows and audits address: unchanged, unless it has a user name or password before its host,
// which is replaced with "xxxxx". It works on the text rather than a parsed URL, so nothing else about the address
// changes (its escaping, say), and two different addresses only look the same when they differ only in their user
// information.
func Redacted(address string) string {
	start, end, ok := authority(address)
	if !ok {
		return address
	}
	at := strings.LastIndex(address[start:end], "@")
	if at < 0 {
		return address
	}
	return address[:start] + "xxxxx" + address[start+at:]
}

// Marks say why an existing list wouldn't be accepted if it were added now, for the Lists page.
const (
	MarkFile        = "file"        // a file: list
	MarkScheme      = "scheme"      // another scheme Pi-hole accepts (ftp, ftps, sftp) or none
	MarkCredentials = "credentials" // a user name or password in the address (shown redacted)
)

// Marks returns the marks for an existing list's address, or nil when it would be accepted with allow_file_lists on.
// A file: list is marked whatever the setting, so they're easy to find.
func Marks(address string) []string {
	var marks []string
	if hasUserInfo(address) {
		marks = append(marks, MarkCredentials)
	}
	scheme := ""
	if i := strings.Index(address, ":"); i > 0 {
		scheme = strings.ToLower(address[:i])
	}
	switch scheme {
	case "http", "https":
	case "file":
		marks = append(marks, MarkFile)
	default:
		marks = append(marks, MarkScheme)
	}
	return marks
}
