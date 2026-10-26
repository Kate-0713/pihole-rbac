// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package v1import moves a v1 installation's settings into a new database: v1's config.json, permissions.json and
// local-users.json become an instance, local users, roles, LDAP settings and mappings, notification channels,
// protected groups and client reset rules.
//
// It works in three stages. Build reads the files into a Plan without contacting anything. Check tests the Pi-hole
// connection and the LDAP bind, looks up the Pi-hole groups the plan needs, and decides what can be switched on.
// Apply writes the plan into a fresh database in one transaction, with an audit row for each thing it creates.
package v1import

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// The v1 file formats, as v1 wrote them. Only the fields the import uses are read; anything else is ignored.

// V1Config is v1's config.json.
type V1Config struct {
	ListenAddr         string   `json:"listen_addr"`
	EnabledAuthMethods []string `json:"enabled_auth_methods"`
	AuthBackend        string   `json:"auth_backend"` // the setting before enabled_auth_methods
	TrustedProxies     []string `json:"trusted_proxies"`
	LocalUsersFile     string   `json:"local_users_file"`
	PermissionsFile    string   `json:"permissions_file"`
	LogFile            string   `json:"log_file"`
	LogRetentionDays   int      `json:"log_retention_days"`

	LDAP struct {
		URL                string `json:"url"`
		BindDN             string `json:"bind_dn"`
		BindPassword       string `json:"bind_password"`
		BaseDN             string `json:"base_dn"`
		UserFilter         string `json:"user_filter"`
		AdminGroupDN       string `json:"admin_group_dn"`
		StaffGroupDN       string `json:"staff_group_dn"`
		ReaderGroupDN      string `json:"reader_group_dn"`
		InsecureSkipVerify bool   `json:"insecure_skip_verify"`
		CACertFile         string `json:"ca_cert_file"`
		AllowCNFallback    *bool  `json:"allow_cn_fallback"` // v1 treated a missing value as true
	} `json:"ldap"`

	Pihole struct {
		BaseURL     string `json:"base_url"`
		APIPassword string `json:"api_password"`
	} `json:"pihole"`

	Notifications struct {
		DiscordWebhooks []struct {
			URL     string `json:"url"`
			Enabled *bool  `json:"enabled"` // missing means enabled
		} `json:"discord_webhooks"`
		MatrixAccounts []struct {
			Homeserver  string `json:"homeserver"`
			RoomID      string `json:"room_id"`
			AccessToken string `json:"access_token"`
			Enabled     *bool  `json:"enabled"`
		} `json:"matrix_accounts"`
		Events          []string `json:"events"`
		ProtectedGroups []string `json:"protected_groups"`
	} `json:"notifications"`

	ClientReset struct {
		Enabled              bool     `json:"enabled"`
		ScheduleTime         string   `json:"schedule_time"` // HH:MM in the v1 host's local time
		TargetClientPrefixes []string `json:"target_client_prefixes"`
		GroupIDMode          bool     `json:"group_id_mode"`
		TargetGroupPrefixes  []string `json:"target_group_prefixes"`
		TargetGroupIDs       []int    `json:"target_group_ids"`
	} `json:"client_reset"`
}

// V1User is one entry of v1's local-users.json.
type V1User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Roles        []string `json:"roles"`
}

// V1 is a v1 installation as read from its files.
type V1 struct {
	Config     V1Config
	ConfigFrom string // the file read
	// Permissions maps v1 role names to v1 permission names, from permissions.json or v1's built-in defaults.
	Permissions     map[string][]string
	PermissionsFrom string // the file read, or "" for v1's built-in defaults
	Users           []V1User
	UsersFrom       string // the file read, or "" when there was none
}

// Files names the v1 files to read. Permissions and Users may be empty: the paths config.json names are then used,
// relative to config.json's directory, as v1 resolved them from its working directory.
type Files struct {
	Config      string
	Permissions string
	Users       string
}

// maxFile is the most of a v1 file that is read. v1's files are a few kilobytes.
const maxFile = 4 << 20

// v1DefaultPermissions is what v1 used when permissions_file wasn't set (rbac.defaultPermissions in v1).
func v1DefaultPermissions() map[string][]string {
	return map[string][]string{
		"admin": {"view_query_log", "view_domains", "edit_domains", "view_clients", "edit_clients", "restart_dns",
			"enable_disable", "reload_config", "manage_config", "run_client_reset", "manage_users"},
		"staff":  {"view_domains", "view_clients", "edit_clients"},
		"reader": {"view_domains", "view_clients"},
	}
}

// Read reads the v1 files. Errors name the file, never what is in it, since config.json holds passwords.
func Read(f Files) (*V1, error) {
	if f.Config == "" {
		return nil, errors.New("the v1 config.json is needed (--config)")
	}
	v := &V1{ConfigFrom: f.Config}
	if err := readJSON(f.Config, &v.Config); err != nil {
		return nil, err
	}
	dir := filepath.Dir(f.Config)

	permPath, permNamed := f.Permissions, f.Permissions != ""
	if !permNamed && v.Config.PermissionsFile != "" {
		permPath = resolve(dir, v.Config.PermissionsFile)
	}
	switch {
	case permPath == "":
		v.Permissions = v1DefaultPermissions()
	default:
		if err := readJSON(permPath, &v.Permissions); err != nil {
			if !permNamed && errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("config.json names permissions_file %q, which isn't at %s: pass the file with --permissions", v.Config.PermissionsFile, permPath)
			}
			return nil, err
		}
		v.PermissionsFrom = permPath
	}

	usersPath, usersNamed := f.Users, f.Users != ""
	if !usersNamed {
		name := v.Config.LocalUsersFile
		if name == "" {
			name = "local-users.json" // v1's default
		}
		usersPath = resolve(dir, name)
	}
	if err := readJSON(usersPath, &v.Users); err != nil {
		// v1 treated a missing users file as no users, so an LDAP-only install may not have one.
		if usersNamed || !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		v.Users = nil
	} else {
		v.UsersFrom = usersPath
	}
	return v, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// readJSON decodes one JSON value from a file. A syntax error says where, but not what was there.
func readJSON(path string, into any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(b) > maxFile {
		return fmt.Errorf("%s is larger than %d MiB, which no v1 file is", path, maxFile>>20)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(into); err != nil {
		var se *json.SyntaxError
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &se):
			return fmt.Errorf("%s isn't valid JSON (at byte %d)", path, se.Offset)
		case errors.As(err, &te):
			return fmt.Errorf("%s: %s has the wrong type (a %s where %s was expected)", path, te.Field, te.Value, te.Type)
		}
		return fmt.Errorf("%s isn't valid JSON", path)
	}
	if dec.More() {
		return fmt.Errorf("%s has more than one JSON value", path)
	}
	return nil
}
