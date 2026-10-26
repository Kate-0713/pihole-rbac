// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1import

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/Kate-0713/pihole-rbac/internal/auth"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/config"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/loginsettings"
	"github.com/Kate-0713/pihole-rbac/internal/notifications"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

// Secrets is what the import needs from the loaded secrets: the master key, and the environment overrides that would
// take the place of a stored secret. *secrets.Manager satisfies it.
type Secrets interface {
	Cipher() *secrets.Cipher // nil without a master key
	InstancePassword(envName string) (secrets.Value, bool)
	LDAPBindPassword() (secrets.Value, bool)
	ChannelSecret(envName string) (secrets.Value, bool)
}

// Options are the choices v1's files can't make.
type Options struct {
	// InstanceName names the imported instance; v1 had only one, without a name. Default DefaultInstanceName.
	InstanceName string
	// TimeZone is the IANA zone of v1's client reset schedule, which ran in the v1 host's local time.
	TimeZone string
	Secrets  Secrets
	// LDAPCAFile is PIHOLE_RBAC_LDAP_CA_FILE, which serve will use for LDAP, so the bind test uses it too.
	LDAPCAFile string
}

// DefaultInstanceName is the imported instance's name unless another is given.
const DefaultInstanceName = "pihole1"

// The v1 roles. admin becomes the builtin admin role; the others become editable roles of the same name.
const (
	v1Admin  = "admin"
	v1Staff  = "staff"
	v1Reader = "reader"
)

// permissionMap turns v1 permission names into v2's. manage_config has no single equivalent and is left out (see
// Build).
var permissionMap = map[string]string{
	"view_query_log":   "querylog.view",
	"view_domains":     "domains.view",
	"edit_domains":     "domains.edit",
	"view_clients":     "clients.view",
	"edit_clients":     "clients.edit",
	"restart_dns":      "dns.restart",
	"enable_disable":   "blocking.toggle",
	"reload_config":    "config.reload",
	"run_client_reset": "clientreset.run",
	"manage_users":     "users.manage",
	"manage_config":    "",
}

// eventMap turns v1 audit action names, used as notification events, into v2's. An empty list means v2 has no such
// event.
var eventMap = map[string][]string{
	"login":                {"login"},
	"logout":               {"logout"},
	"toggle_blocking":      {"blocking_set"},
	"restart_dns":          {"dns_restart"},
	"add_domain":           {"domain_add"},
	"update_domain_groups": {"domain_update"},
	"update_client_groups": {"client_update"},
	"client_reset":         {"client_reset"},
	"reload_config":        {"config_reload"},
	"reload_permissions":   {"config_reload"},
	"update_permissions":   {"role_create", "role_update", "role_grants", "role_delete"},
	"update_config":        {"settings_update"},
	"create_user":          {"user_create"},
	"update_user_roles":    {"user_roles"},
	"reset_user_password":  {"user_password"},
	"delete_user":          {"user_delete"},
	"login_locked":         {"login"},
	"restart_app":          nil,
	"csrf_rejected":        nil,
}

// Plan is what the import will create. Nothing in it is secret when printed: secret values are secrets.Value.
type Plan struct {
	From      V1Files
	Instance  PlannedInstance
	Roles     []PlannedRole // staff and reader; admin is the builtin role
	Users     []PlannedUser
	LDAP      *PlannedLDAP // nil when v1 had no LDAP server
	Mappings  []PlannedMapping
	Methods   []auth.Method // the login methods to save
	Channels  []PlannedChannel
	Protected []string // Pi-hole group names, on the instance
	Rules     []PlannedRule
	Schedule  *loginsettings.ResetSchedule // nil to leave the default (off)

	Checked bool   // Check has run: the connection test and the bind test
	Offline string // why Check didn't contact anything, if it didn't

	Errors   []string // these stop --apply
	Warnings []string
	ToDo     []string // things to do by hand after importing
}

// V1Files records which files the plan was built from.
type V1Files struct {
	Config, Permissions, Users string // "" for permissions means v1's built-in defaults; for users, no file
}

// PlannedInstance is the imported Pi-hole instance.
type PlannedInstance struct {
	Input    instances.Input // normalized; its Password is unset
	Password secrets.Value   // v1's api_password; zero if v1 had none
	Store    bool            // seal Password into the database (a master key is set)
	EnvSet   bool            // Input.EnvName's variable is set now
	envValue secrets.Value
	Test     string // "ok", or an error code, once checked
	TestErr  string // the test's error, for the report
	Enable   bool
}

// servePassword is the password serve will use for the instance, if it will have one.
func (p PlannedInstance) servePassword() (secrets.Value, bool) {
	switch {
	case p.EnvSet:
		return p.envValue, true
	case p.Store && !p.Password.IsZero():
		return p.Password, true
	}
	return secrets.Value{}, false
}

// PlannedRole is a v1 role other than admin.
type PlannedRole struct {
	Name        string
	Description string
	Permissions []string // v2 names, granted at scope all
}

// PlannedUser is a v1 local user.
type PlannedUser struct {
	Username string
	Hash     string   // v1's bcrypt hash, kept so the password doesn't change
	Roles    []string // v1 role names: admin, staff, reader
}

// PlannedLDAP is v1's LDAP server.
type PlannedLDAP struct {
	Settings auth.LDAPSettings // normalized
	Password secrets.Value     // v1's bind_password
	Store    bool              // seal it into the database
	EnvSet   bool              // PIHOLE_RBAC_LDAP_BIND_PASSWORD is set now
	envValue secrets.Value
	Want     bool   // v1 had LDAP login on
	Test     string // "ok" or "failed", once checked
	TestErr  string
	Enable   bool
}

func (p PlannedLDAP) servePassword() (secrets.Value, bool) {
	switch {
	case p.EnvSet:
		return p.envValue, true
	case p.Store && !p.Password.IsZero():
		return p.Password, true
	}
	return secrets.Value{}, false
}

// PlannedMapping maps an LDAP group to a role.
type PlannedMapping struct {
	Role string // v1 role name
	DN   string
	Norm string
}

// PlannedChannel is a v1 Discord webhook or Matrix account.
type PlannedChannel struct {
	Input  notifications.Input // normalized; Secret is v1's secret, or nil if v1 had none
	From   string              // where it was in config.json, e.g. "discord_webhooks[0]"
	Store  bool                // seal the secret into the database
	EnvSet bool                // Input.EnvName's variable is set now
}

// PlannedRule is a client reset rule on the instance.
type PlannedRule struct {
	Prefix   string
	Match    clientreset.Match
	Groups   []string
	groupIDs []int // v1's group_id_mode IDs, turned into names by Check
}

func (p *Plan) errorf(format string, args ...any) {
	p.Errors = append(p.Errors, fmt.Sprintf(format, args...))
}
func (p *Plan) warnf(format string, args ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...))
}
func (p *Plan) todof(format string, args ...any) {
	p.ToDo = append(p.ToDo, fmt.Sprintf(format, args...))
}

// Build works out what the import would create, without contacting anything. Problems that would make the result
// wrong are Errors; things that change on the way to v2 are Warnings; things to do by hand are ToDo.
func Build(v *V1, opts Options) *Plan {
	p := &Plan{From: V1Files{Config: v.ConfigFrom, Permissions: v.PermissionsFrom, Users: v.UsersFrom}}
	cipher := opts.Secrets.Cipher()
	p.buildInstance(v, opts, cipher)
	p.buildRoles(v)
	p.buildUsers(v)
	p.buildLDAP(v, opts, cipher)
	p.buildChannels(v, opts, cipher)
	p.buildClientReset(v, opts)
	p.buildAdvice(v)
	return p
}

// envNameFor makes an env name from a display name: upper case, anything outside A-Z and 0-9 an underscore.
func envNameFor(name, fallback string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := strings.Trim(b.String(), "_")
	if s == "" || len(s) > 64 {
		return fallback
	}
	return s
}

func (p *Plan) buildInstance(v *V1, opts Options, cipher *secrets.Cipher) {
	name := strings.TrimSpace(opts.InstanceName)
	if name == "" {
		name = DefaultInstanceName
	}
	in := instances.Input{Name: name, BaseURL: v.Config.Pihole.BaseURL, TLSMode: piholeapi.TLSVerify}
	if cipher == nil {
		in.EnvName = envNameFor(name, "PIHOLE")
	}
	norm, err := in.Normalize()
	if err != nil {
		p.errorf("The instance (pihole.base_url %q, named %q): %s", v.Config.Pihole.BaseURL, name, err)
		norm = in
	}
	p.Instance = PlannedInstance{Input: norm, Store: cipher != nil}
	if v.Config.Pihole.APIPassword == "" {
		p.warnf("config.json has no pihole.api_password, so the instance can't be switched on until it has one.")
	} else {
		p.Instance.Password = secrets.NewValue([]byte(v.Config.Pihole.APIPassword))
	}
	if norm.EnvName != "" {
		if val, ok := opts.Secrets.InstancePassword(norm.EnvName); ok {
			p.Instance.EnvSet, p.Instance.envValue = true, val
			if !p.Instance.Password.IsZero() && !val.Equal(p.Instance.Password) {
				p.warnf("%s is set, but not to v1's Pi-hole password. The instance will use the variable, so that is what is tested.",
					secrets.InstanceVar(norm.EnvName))
			}
		} else if !p.Instance.Password.IsZero() {
			p.todof("Set %s to the Pi-hole password from v1's config.json (no master key is set, so it can't be stored), restart, then enable %s on Admin → Instances.",
				secrets.InstanceVar(norm.EnvName), name)
		}
	}
}

// buildRoles checks permissions.json as v1 did (unknown roles or permissions stop it) and plans the staff and reader
// roles.
func (p *Plan) buildRoles(v *V1) {
	from := "v1's built-in permissions"
	if v.PermissionsFrom != "" {
		from = "permissions.json"
	}
	known := []string{v1Admin, v1Staff, v1Reader}
	var names []string
	for r := range v.Permissions {
		names = append(names, r)
	}
	slices.Sort(names)
	for _, r := range names {
		if !slices.Contains(known, r) {
			p.errorf("%s has a role %q; v1 only had admin, staff and reader, so it would have refused this file.", from, r)
		}
		for _, perm := range v.Permissions[r] {
			if _, ok := permissionMap[perm]; !ok {
				p.errorf("%s gives %s the permission %q, which v1 didn't have, so it would have refused this file.", from, r, perm)
			}
		}
	}

	admin := v.Permissions[v1Admin]
	var missing []string
	for _, perm := range v1DefaultPermissions()[v1Admin] {
		if !slices.Contains(admin, perm) {
			missing = append(missing, perm)
		}
	}
	if len(missing) > 0 {
		p.warnf("v1's admin role didn't have %s. It becomes v2's builtin admin role, which has every permission and can't be changed: anyone who was an admin can now do these too.",
			strings.Join(missing, ", "))
	}

	for _, r := range []string{v1Staff, v1Reader} {
		perms, ok := v.Permissions[r]
		role := PlannedRole{Name: r, Description: fmt.Sprintf("Imported from v1's %s role.", r), Permissions: []string{}}
		if !ok {
			p.warnf("%s doesn't list the %s role, so v1 gave it no permissions; it is imported with none.", from, r)
		}
		for _, perm := range perms {
			v2, known := permissionMap[perm]
			switch {
			case !known:
				// Reported above.
			case v2 == "":
				p.warnf("v1's %s role had manage_config. It isn't imported: v2 splits it into settings.manage, instances.manage, notifications.manage and roles.manage, so grant whichever of those %s needs on Admin → Roles.",
					r, r)
			case !slices.Contains(role.Permissions, v2):
				role.Permissions = append(role.Permissions, v2)
			}
		}
		slices.Sort(role.Permissions)
		p.Roles = append(p.Roles, role)
	}
}

func (p *Plan) buildUsers(v *V1) {
	seen := map[string]string{}
	for i, u := range v.Users {
		name := auth.NormalizeUsername(u.Username)
		where := fmt.Sprintf("local-users.json entry %d (%q)", i+1, u.Username)
		if err := auth.ValidateUsername(name); err != nil {
			p.errorf("%s: v2 usernames are 1-64 characters of a-z, 0-9, '.', '_' and '-', starting with a letter or digit. Rename it in a copy of the file.", where)
			continue
		}
		if name != u.Username {
			p.warnf("The local user %q becomes %q: v2 usernames are lower case.", u.Username, name)
		}
		if other, dup := seen[name]; dup {
			p.errorf("%s: it is the same user as %q once lower-cased. Remove one of them from a copy of the file.", where, other)
			continue
		}
		seen[name] = u.Username
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			p.errorf("%s: its password_hash isn't a bcrypt hash.", where)
			continue
		}
		var roles []string
		for _, r := range u.Roles {
			if r != v1Admin && r != v1Staff && r != v1Reader {
				p.errorf("%s has the role %q; v1 only had admin, staff and reader.", where, r)
				continue
			}
			if !slices.Contains(roles, r) {
				roles = append(roles, r)
			}
		}
		if len(u.Roles) == 0 {
			p.warnf("The local user %q has no roles, so it can log in but do nothing.", name)
		}
		p.Users = append(p.Users, PlannedUser{Username: name, Hash: u.PasswordHash, Roles: roles})
	}
	if p.admins() == 0 {
		p.warnf("No local user is an admin, so first-run setup stays open: once imported, start the app and finish setup with its setup token to create one.")
	}
}

// admins counts the planned local admins.
func (p *Plan) admins() int {
	n := 0
	for _, u := range p.Users {
		if slices.Contains(u.Roles, v1Admin) {
			n++
		}
	}
	return n
}

func (p *Plan) buildLDAP(v *V1, opts Options, cipher *secrets.Cipher) {
	l := v.Config.LDAP
	methods := v.Config.EnabledAuthMethods
	if len(methods) == 0 && v.Config.AuthBackend != "" {
		methods = []string{v.Config.AuthBackend}
	}
	want := false
	for _, m := range methods {
		switch auth.Method(m) {
		case auth.MethodLocal:
			if !slices.Contains(p.Methods, auth.MethodLocal) {
				p.Methods = append(p.Methods, auth.MethodLocal)
			}
		case auth.MethodLDAP:
			want = true
			if !slices.Contains(p.Methods, auth.MethodLDAP) {
				p.Methods = append(p.Methods, auth.MethodLDAP)
			}
		default:
			p.errorf("config.json enables the login method %q; v1 only had local and ldap.", m)
		}
	}
	if !slices.Contains(p.Methods, auth.MethodLocal) {
		p.Methods = append(p.Methods, auth.MethodLocal)
		if want {
			p.warnf("v1 only allowed LDAP login. v2 always keeps local login on, after LDAP here, so a local admin can get in when LDAP is down.")
		}
	}

	if l.URL == "" {
		if want {
			p.warnf("config.json turns LDAP login on but has no ldap.url, so LDAP login stays off.")
			p.dropLDAP()
		}
		if l.AdminGroupDN != "" || l.StaffGroupDN != "" || l.ReaderGroupDN != "" {
			p.warnf("config.json has LDAP group DNs but no LDAP server, so they aren't imported.")
		}
		return
	}

	ls := auth.LDAPSettings{URL: l.URL, BindDN: l.BindDN, BaseDN: l.BaseDN, UserFilter: l.UserFilter, TLSMode: auth.LDAPTLSVerify}
	if l.InsecureSkipVerify {
		ls.TLSMode = auth.LDAPTLSInsecure
		p.warnf("v1 skipped checking the LDAP server's certificate (insecure_skip_verify), so v2's LDAP TLS mode is insecure. Switch it to verify on Admin → LDAP once the CA is set up.")
	}
	norm, err := loginsettings.NormalizeLDAP(ls)
	if err != nil {
		if want {
			p.errorf("The LDAP settings in config.json: %s", err)
		} else {
			p.warnf("The LDAP settings in config.json aren't imported, since LDAP login was off: %s", err)
		}
		p.dropLDAP()
		return
	}
	pl := &PlannedLDAP{Settings: norm, Store: cipher != nil, Want: want}
	if strings.HasPrefix(norm.URL, "ldap://") {
		p.warnf("The LDAP server is ldap://, without TLS, so passwords cross the network in the clear, as they did in v1. Switch to ldaps:// on Admin → LDAP when you can.")
	}
	if l.BindPassword != "" {
		pl.Password = secrets.NewValue([]byte(l.BindPassword))
	} else {
		p.warnf("config.json has no ldap.bind_password, so LDAP login can't be switched on until it has one.")
	}
	if val, ok := opts.Secrets.LDAPBindPassword(); ok {
		pl.EnvSet, pl.envValue = true, val
		if !pl.Password.IsZero() && !val.Equal(pl.Password) {
			p.warnf("PIHOLE_RBAC_LDAP_BIND_PASSWORD is set, but not to v1's bind password. v2 will use the variable, so that is what is tested.")
		}
	} else if cipher == nil && !pl.Password.IsZero() {
		p.todof("Set PIHOLE_RBAC_LDAP_BIND_PASSWORD to the bind password from v1's config.json (no master key is set, so it can't be stored), restart, then turn LDAP login on on Admin → LDAP.")
	}
	if l.CACertFile != "" {
		if opts.LDAPCAFile == "" {
			p.todof("v1 trusted the LDAP server through %s. Copy that CA file to this host and set PIHOLE_RBAC_LDAP_CA_FILE to its path before starting the app. The bind test ran without it.",
				l.CACertFile)
		}
		if l.AllowCNFallback == nil || *l.AllowCNFallback {
			p.warnf("v1 accepted an LDAP certificate that names the host only in its Common Name; v2 doesn't unless allow_cn_fallback is on. If LDAP logins fail with a certificate error, and only if the server's certificate has no matching Subject Alternative Name, turn it on on Admin → LDAP.")
		}
	}
	p.LDAP = pl

	for _, g := range []struct{ role, dn string }{{v1Admin, l.AdminGroupDN}, {v1Staff, l.StaffGroupDN}, {v1Reader, l.ReaderGroupDN}} {
		if strings.TrimSpace(g.dn) == "" {
			continue
		}
		n, err := auth.NormalizeDN(strings.TrimSpace(g.dn))
		if err != nil {
			p.errorf("config.json's ldap.%s_group_dn isn't a valid DN.", g.role)
			continue
		}
		p.Mappings = append(p.Mappings, PlannedMapping{Role: g.role, DN: strings.TrimSpace(g.dn), Norm: n})
	}
}

func (p *Plan) dropLDAP() {
	p.Methods = slices.DeleteFunc(p.Methods, func(m auth.Method) bool { return m == auth.MethodLDAP })
}

func (p *Plan) buildChannels(v *V1, opts Options, cipher *secrets.Cipher) {
	n := v.Config.Notifications
	var events []string
	for _, e := range n.Events {
		mapped, ok := eventMap[strings.ToLower(e)]
		switch {
		case !ok:
			p.warnf("The notification event %q isn't one v1 sent, so it is left out.", e)
		case len(mapped) == 0:
			p.warnf("v2 has no %q event, so channels won't be sent it.", e)
		}
		for _, m := range mapped {
			if !slices.Contains(events, m) {
				events = append(events, m)
			}
		}
	}
	// v1 sent protected-group alerts to every destination, whatever its events.
	for _, g := range n.ProtectedGroups {
		g = strings.TrimSpace(g)
		if c := utf8.RuneCountInString(g); c == 0 || c > 255 || strings.IndexFunc(g, unicode.IsControl) >= 0 {
			p.warnf("The protected group %q isn't a usable Pi-hole group name, so it is left out.", g)
			continue
		}
		if !slices.ContainsFunc(p.Protected, func(x string) bool { return strings.EqualFold(x, g) }) {
			p.Protected = append(p.Protected, g)
		}
	}
	if len(p.Protected) > 0 {
		events = append(events, notify.EventProtectedGroupAdd)
	}

	add := func(in notifications.Input, from string, secret string) {
		if secret != "" {
			s := secrets.NewValue([]byte(secret))
			in.Secret = &s
		}
		if cipher == nil {
			in.EnvName = envNameFor(in.Name, "CHANNEL")
		}
		in.Events = events
		norm, err := in.Normalize()
		if err != nil {
			p.warnf("config.json's notifications.%s isn't imported: %s", from, err)
			return
		}
		pc := PlannedChannel{Input: norm, From: from, Store: cipher != nil && norm.Secret != nil}
		if norm.EnvName != "" {
			if val, ok := opts.Secrets.ChannelSecret(norm.EnvName); ok {
				pc.EnvSet = true
				if norm.Secret != nil && !sameChannelSecret(norm.Kind, val, *norm.Secret) {
					p.warnf("%s is set, but not to the secret of notifications.%s. The channel will use the variable.", secrets.ChannelVar(norm.EnvName), from)
				}
			} else if norm.Secret != nil {
				what := "webhook URL"
				if norm.Kind == notify.Matrix {
					what = "access token"
				}
				p.todof("Set %s to the %s of notifications.%s in v1's config.json (no master key is set, so it can't be stored), then restart.",
					secrets.ChannelVar(norm.EnvName), what, from)
			}
		}
		if norm.Secret == nil && !pc.EnvSet {
			p.warnf("notifications.%s has no secret, so %s can't send until one is stored.", from, norm.Name)
		}
		p.Channels = append(p.Channels, pc)
	}
	for i, d := range n.DiscordWebhooks {
		add(notifications.Input{Kind: notify.Discord, Name: fmt.Sprintf("Discord %d", i+1), Enabled: d.Enabled == nil || *d.Enabled},
			fmt.Sprintf("discord_webhooks[%d]", i), d.URL)
	}
	for i, m := range n.MatrixAccounts {
		mc := notify.MatrixConfig{Homeserver: m.Homeserver, RoomID: m.RoomID}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(m.Homeserver)), "http://") {
			mc.AllowHTTP = true
			p.warnf("notifications.matrix_accounts[%d] uses plain HTTP, so the channel allows it; its access token crosses the network in the clear.", i)
		}
		add(notifications.Input{Kind: notify.Matrix, Name: fmt.Sprintf("Matrix %d", i+1), Enabled: m.Enabled == nil || *m.Enabled, Matrix: mc},
			fmt.Sprintf("matrix_accounts[%d]", i), m.AccessToken)
	}
	if len(p.Channels) == 0 && len(p.Protected) > 0 {
		p.warnf("config.json lists protected groups but no destinations: they are imported, but nothing will be sent until a channel subscribes to protected_group_add.")
	}
}

// sameChannelSecret compares two secrets for a channel, Discord URLs in canonical form.
func sameChannelSecret(kind notify.Kind, a, b secrets.Value) bool {
	if kind == notify.Discord {
		ca, _, errA := notify.ParseDiscordWebhook(a.Reveal())
		cb, _, errB := notify.ParseDiscordWebhook(b.Reveal())
		return errA == nil && errB == nil && ca == cb
	}
	return a.Equal(b)
}

func (p *Plan) buildClientReset(v *V1, opts Options) {
	cr := v.Config.ClientReset
	var prefixes []string
	for _, pre := range cr.TargetClientPrefixes {
		if pre != "" && !slices.Contains(prefixes, pre) {
			prefixes = append(prefixes, pre)
		}
	}
	if len(prefixes) > 0 {
		switch {
		case cr.GroupIDMode && len(cr.TargetGroupIDs) == 0, !cr.GroupIDMode && len(cr.TargetGroupPrefixes) == 0:
			p.warnf("client_reset names client prefixes but no target groups, so v1 refused to run it; no rules are imported.")
		case cr.GroupIDMode:
			for _, pre := range prefixes {
				p.Rules = append(p.Rules, PlannedRule{Prefix: pre, Match: clientreset.MatchNames, groupIDs: slices.Clone(cr.TargetGroupIDs)})
			}
		default:
			for _, pre := range prefixes {
				p.Rules = append(p.Rules, PlannedRule{Prefix: pre, Match: clientreset.MatchPrefixes, Groups: slices.Clone(cr.TargetGroupPrefixes)})
			}
		}
	}

	if cr.ScheduleTime == "" {
		return
	}
	sched := loginsettings.ResetSchedule{Enabled: cr.Enabled, Time: cr.ScheduleTime, TimeZone: opts.TimeZone}
	if len(sched.Time) == 4 && sched.Time[1] == ':' { // v1 accepted "3:00"
		sched.Time = "0" + sched.Time
	}
	if sched.TimeZone == "" {
		if cr.Enabled {
			p.errorf("v1 ran client reset daily at %s in its host's local time. Give that time zone with --time-zone, such as --time-zone Europe/London.", cr.ScheduleTime)
			return
		}
		sched.TimeZone = "UTC"
	}
	if err := sched.Validate(); err != nil {
		if cr.Enabled {
			p.errorf("The client reset schedule (%s, %s): %s", cr.ScheduleTime, sched.TimeZone, err)
		} else {
			p.warnf("The client reset schedule (%s, %s) isn't imported: %s", cr.ScheduleTime, sched.TimeZone, err)
		}
		return
	}
	if len(p.Rules) == 0 && cr.Enabled {
		p.warnf("The client reset schedule is on, but there are no rules for it to run.")
	}
	p.Schedule = &sched
}

// checkRules validates the rules whose groups are known, as the rules page does.
func (p *Plan) checkRules() {
	var in []clientreset.RuleInput
	for _, r := range p.Rules {
		if r.groupIDs == nil {
			in = append(in, clientreset.RuleInput{Scope: clientreset.ScopeInstance, ID: 1, Prefix: r.Prefix, Match: r.Match, Groups: r.Groups})
		}
	}
	if _, err := clientreset.CheckRules(in); err != nil {
		p.errorf("The client reset settings: %s", err)
	}
}

func (p *Plan) buildAdvice(v *V1) {
	if len(v.Config.TrustedProxies) > 0 {
		p.todof("v1 trusted these reverse proxies: set PIHOLE_RBAC_TRUSTED_PROXIES=%q.", strings.Join(v.Config.TrustedProxies, ","))
	}
	if v.Config.ListenAddr != "" && v.Config.ListenAddr != ":8080" {
		p.todof("v1 listened on %s; v2 listens on :8080 unless PIHOLE_RBAC_LISTEN says otherwise. Point the reverse proxy at the right one.", v.Config.ListenAddr)
	}
	if v.Config.LogFile != "" {
		p.todof("v1 wrote daily log files beside %s. v2 writes them only when PIHOLE_RBAC_LOG_DIR is set (the LXC install sets /var/log/pihole-rbac); otherwise it logs to stdout only.", v.Config.LogFile)
		switch days := v.Config.LogRetentionDays; {
		case days <= 0:
			p.todof("v1 kept its log files forever: set PIHOLE_RBAC_LOG_RETENTION_DAYS=0 to do the same (v2 keeps %d days unless told otherwise).", config.DefaultLogRetentionDays)
		case days != config.DefaultLogRetentionDays:
			p.todof("v1 kept %d days of log files: set PIHOLE_RBAC_LOG_RETENTION_DAYS=%d to do the same (v2 keeps %d days unless told otherwise).", days, days, config.DefaultLogRetentionDays)
		}
	}
	p.todof("Sessions aren't carried over (v1's session_key isn't used): everyone logs in again.")
}
