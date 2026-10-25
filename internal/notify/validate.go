// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ValidationError names the setting that is wrong. Messages never include a secret: a Discord webhook URL is one.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

func invalid(field, format string, args ...any) *ValidationError {
	return &ValidationError{Field: field, Message: fmt.Sprintf(format, args...)}
}

const (
	maxURL        = 2048
	maxRoomID     = 255
	maxToken      = 1024
	discordPrefix = "/api/webhooks/"
)

var (
	webhookIDPattern    = regexp.MustCompile(`^[0-9]{1,20}$`)
	webhookTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
	// A room ID, not an alias: !opaque:server, where the server may carry a port.
	roomIDPattern = regexp.MustCompile(`^![A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(:[0-9]{1,5})?$`)
)

// discordHosts are the only hosts a Discord webhook may point at. Checking the host here, rather than resolving it,
// is what stops a channel being used to send requests into the local network.
var discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true}

// ParseDiscordWebhook checks a Discord webhook URL and returns it in canonical form with its webhook ID, which isn't
// secret and identifies the webhook on the page. The token in the URL is the secret, so no error repeats the URL.
func ParseDiscordWebhook(raw string) (canonical, webhookID string, err error) {
	const field = "secret"
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", invalid(field, "Give the webhook URL.")
	}
	if len(raw) > maxURL {
		return "", "", invalid(field, "That webhook URL is too long.")
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Opaque != "" {
		return "", "", invalid(field, "That isn't a URL.")
	}
	if u.Scheme != "https" {
		return "", "", invalid(field, "A Discord webhook URL starts with https://.")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", "", invalid(field, "A Discord webhook URL has no username, query or fragment.")
	}
	host := strings.ToLower(u.Hostname())
	if !discordHosts[host] || (u.Port() != "" && u.Port() != "443") {
		return "", "", invalid(field, "A Discord webhook URL must be on discord.com or discordapp.com.")
	}
	id, token, ok := strings.Cut(strings.TrimPrefix(u.Path, discordPrefix), "/")
	if !strings.HasPrefix(u.Path, discordPrefix) || !ok || !webhookIDPattern.MatchString(id) ||
		!webhookTokenPattern.MatchString(token) || u.RawPath != "" {
		return "", "", invalid(field, "That isn't a Discord webhook URL: it should look like https://discord.com/api/webhooks/<id>/<token>.")
	}
	return "https://" + host + discordPrefix + id + "/" + token, id, nil
}

// MatrixConfig is a Matrix channel's non-secret settings. The access token is the secret.
type MatrixConfig struct {
	Homeserver string `json:"homeserver"`
	RoomID     string `json:"room_id"`
	AllowHTTP  bool   `json:"allow_http"`
}

// Normalize checks the settings and returns them with the homeserver in canonical form: lower-case scheme and host,
// no trailing slash. A homeserver may be on the local network (it often is), but plain HTTP needs AllowHTTP.
func (c MatrixConfig) Normalize() (MatrixConfig, error) {
	raw := strings.TrimSpace(c.Homeserver)
	if raw == "" {
		return c, invalid("homeserver", "Give the homeserver's URL.")
	}
	if len(raw) > maxURL {
		return c, invalid("homeserver", "That homeserver URL is too long.")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return c, invalid("homeserver", "That isn't a URL.")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !c.AllowHTTP {
			return c, invalid("homeserver", "The homeserver must use https://, unless plain HTTP is allowed for this channel.")
		}
	default:
		return c, invalid("homeserver", "The homeserver URL starts with https:// (or http://).")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return c, invalid("homeserver", "A homeserver URL has no username, query or fragment.")
	}
	if p := u.Port(); p != "" {
		if n := len(p); n > 5 || strings.Trim(p, "0123456789") != "" {
			return c, invalid("homeserver", "That port isn't a number.")
		}
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	room := strings.TrimSpace(c.RoomID)
	if len(room) > maxRoomID || !roomIDPattern.MatchString(room) {
		return c, invalid("room_id", "Give the room's internal ID, like !abcdefg:example.org (not an alias starting with #).")
	}
	return MatrixConfig{
		Homeserver: strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path,
		RoomID:     room,
		AllowHTTP:  c.AllowHTTP,
	}, nil
}

// CheckMatrixToken checks an access token can go in an Authorization header as it is.
func CheckMatrixToken(token string) error {
	if token == "" {
		return invalid("secret", "Give the access token.")
	}
	if len(token) > maxToken {
		return invalid("secret", "That access token is too long.")
	}
	for i := 0; i < len(token); i++ {
		if c := token[i]; c <= ' ' || c > '~' {
			return invalid("secret", "An access token has no spaces or special characters.")
		}
	}
	return nil
}
