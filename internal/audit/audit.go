// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audit records security-relevant events: logins, logouts, and every write to Pi-hole, users, roles or
// settings. Read-only actions aren't audited.
//
// Each event is recorded twice. Insert writes the audit_log row, inside the same transaction as the change it
// describes, so the change and its record commit or roll back together. Log then writes the v1-style AUDIT line to
// the log stream once the transaction has committed, so the line can be grepped or routed separately:
//
//	journalctl -u pihole-rbac | grep AUDIT
//
// Secret values never belong in an Entry: not in Target, not in Detail, not in the error.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync/atomic"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Result values stored in audit_log.result.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Actions. They are constants from our own code, which is why the AUDIT line can write them unquoted.
const (
	ActionLogin      = "login"
	ActionLogout     = "logout"
	ActionSetup      = "setup"       // first-run setup completed (or a wrong setup token)
	ActionSetupToken = "setup_token" // a new setup token was made with `pihole-rbac setup --print-token`
	ActionResetAdmin = "reset_admin" // `pihole-rbac user reset-admin` was run

	// Refusals of a state-changing request because the user lacks a permission, or would grant more than they hold.
	ActionPermissionDenied = "permission_denied"

	// Roles, grants and LDAP mappings.
	ActionRoleCreate        = "role_create"
	ActionRoleUpdate        = "role_update"
	ActionRoleTOTPUpdate    = "role_totp_update" // a role started or stopped requiring two-factor login
	ActionRoleGrants        = "role_grants"
	ActionRoleDelete        = "role_delete"
	ActionLDAPMappingAdd    = "ldap_mapping_add"
	ActionLDAPMappingRemove = "ldap_mapping_remove"
	ActionLDAPMappingCheck  = "ldap_mapping_check" // an admin asked the directory about a group DN

	// Users.
	ActionUserCreate     = "user_create"
	ActionUserRoles      = "user_roles"
	ActionUserTOTPPolicy = "user_totp_policy" // a user's own two-factor setting changed: roles, required or exempt
	ActionUserDisable    = "user_disable"
	ActionUserEnable     = "user_enable"
	ActionUserDelete     = "user_delete"
	ActionUserPassword   = "user_password"   // an admin set a local user's password; never the value
	ActionPasswordChange = "password_change" // a user changed their own password; never the value

	ActionTOTPEnable              = "totp_enable"               // a user turned two-factor login on
	ActionTOTPDisable             = "totp_disable"              // a user turned theirs off, or an admin removed it (detail.by)
	ActionRecoveryCodeUsed        = "recovery_code_used"        // a recovery code was used in place of a six-digit code
	ActionRecoveryCodesRegenerate = "recovery_codes_regenerate" // a user replaced their recovery codes

	// Pi-hole instances. An enable or edit refused because the connection test failed is recorded as a failure.
	// ActionInstanceTest only appears as the attempted action of a permission_denied row: a test changes nothing.
	ActionInstanceCreate   = "instance_create"
	ActionInstanceUpdate   = "instance_update"
	ActionInstanceEnable   = "instance_enable"
	ActionInstanceDisable  = "instance_disable"
	ActionInstanceDelete   = "instance_delete"
	ActionInstancePassword = "instance_password" // a new app password stored; never the value
	ActionInstanceTest     = "instance_test"

	// Instance groups.
	ActionGroupCreate = "group_create"
	ActionGroupUpdate = "group_update"
	ActionGroupDelete = "group_delete"
	// A mirrored group's member made to match the primary: one row per member, listing what was added, changed and
	// deleted.
	ActionGroupReconcile = "group_reconcile"

	// Pi-hole writes, recorded after the call with the instance and its result. Target is the API target (i-<id>);
	// the detail names the item. A write Pi-hole refused is a failure with its message.
	ActionBlockingSet  = "blocking_set"
	ActionDNSRestart   = "dns_restart"
	ActionDomainAdd    = "domain_add"
	ActionDomainUpdate = "domain_update"
	ActionDomainDelete = "domain_delete"
	ActionClientUpdate = "client_update"

	// Pi-hole groups (not instance groups), recorded like other Pi-hole writes. A change to the enabled flag is
	// piholegroup_enable or piholegroup_disable, with any rename or comment change in the same row, so a channel can
	// hear about just those; piholegroup_update is a rename or comment change alone. A rename or delete lists the
	// app's references to the group it changed or left (references_updated, references_to_check, references).
	ActionPiholeGroupAdd     = "piholegroup_add"
	ActionPiholeGroupUpdate  = "piholegroup_update"
	ActionPiholeGroupEnable  = "piholegroup_enable"
	ActionPiholeGroupDisable = "piholegroup_disable"
	ActionPiholeGroupDelete  = "piholegroup_delete"

	// Subscribed lists (adlists), since v2.3.0.
	ActionListAdd    = "list_add"
	ActionListUpdate = "list_update"
	ActionListDelete = "list_delete"

	// Local DNS records and CNAMEs, since v2.4.0: once per instance, with the record's key and Pi-hole's string, and
	// the reason. A change (add then delete, since Pi-hole has no edit) is one _update row.
	ActionDNSRecordAdd    = "dnsrecord_add"
	ActionDNSRecordUpdate = "dnsrecord_update"
	ActionDNSRecordDelete = "dnsrecord_delete"
	ActionCNAMEAdd        = "cname_add"
	ActionCNAMEUpdate     = "cname_update"
	ActionCNAMEDelete     = "cname_delete"

	// DHCP, since v2.7.0: a lease deleted, a static lease added, changed or deleted, or the settings changed, on one
	// instance. Settings and static lease changes restart FTL on it. Reading isn't audited.
	ActionDHCPLeaseDelete    = "dhcp_lease_delete"
	ActionDHCPStaticAdd      = "dhcp_static_add"
	ActionDHCPStaticUpdate   = "dhcp_static_update"
	ActionDHCPStaticDelete   = "dhcp_static_delete"
	ActionDHCPSettingsUpdate = "dhcp_settings_update"

	// Schedules, since v2.5.0: changes to schedules by a user, and once per instance an edge (a window's start or end)
	// or its retry sent something to, or failed on, by (system).
	ActionScheduleCreate = "schedule_create"
	ActionScheduleUpdate = "schedule_update"
	ActionScheduleDelete = "schedule_delete"
	ActionScheduleRun    = "schedule_run"

	// Temporary client group changes (v2.6.0). Set and end are one row per member, by the user. Revert is the
	// app's own, by SystemUser, once per member that was changed or failed on.
	ActionClientTempSet    = "client_temp_set"
	ActionClientTempUpdate = "client_temp_update"
	ActionClientTempEnd    = "client_temp_end"
	ActionClientTempRevert = "client_temp_revert"

	// Gravity runs, since v2.3.0: when a run starts, and per instance when its part ends.
	ActionGravityStart = "gravity_start"
	ActionGravityRun   = "gravity_run"

	// Client reset: one row per instance a run changed or failed on (a run that found nothing to change writes none),
	// listing the clients reset and those that failed, with Pi-hole groups by name. A scheduled run is SystemUser's.
	ActionClientReset = "client_reset"
	// The client reset rules were replaced; the detail lists the rules added and removed.
	ActionClientResetRules = "client_reset_rules"

	// Sessions.
	ActionLDAPRecheck   = "ldap_recheck"   // an LDAP user's session roles changed, or their sessions ended, at a recheck
	ActionSessionRevoke = "session_revoke" // a session was ended from the sessions page, by its user or an admin

	// API tokens. Rows never carry a token, its secret or its hash: a token is named by its name and public ID.
	ActionTokenCreate     = "token_create"      // a user made an API token; the detail lists its expiry and grants
	ActionTokenRevoke     = "token_revoke"      // a token was revoked by its owner or an admin (detail.by)
	ActionTokenExpiredUse = "token_expired_use" // an expired token was used, at most once an hour per token

	// Settings. The detail lists the fields that changed; a bind password shows as stored or confirmed, never its value.
	ActionSettingsUpdate = "settings_update"

	// System.
	ActionConfigReload = "config_reload" // secrets were reloaded; the detail lists the names that changed or failed
	// `pihole-rbac rotate-key` re-encrypted the stored secrets under a new master key; the detail lists them by table and
	// name, never a value.
	ActionRotateKey  = "rotate_key"
	ActionAppRestart = "app_restart" // the app was restarted from the System page
	// Updates. A request names the version asked for, or "latest". The outcomes are written by the app as SystemUser
	// once the updater has finished, since the updater itself writes only update_requests.
	ActionUpdateRequest    = "update_request"
	ActionUpdateDone       = "update_done"
	ActionUpdateFailed     = "update_failed"      // the updater stopped before replacing anything
	ActionUpdateRolledBack = "update_rolled_back" // the new version didn't become healthy; the previous one is back
	// Notification channels. The detail lists what changed; a secret shows as stored or confirmed, never its value.
	ActionChannelCreate = "channel_create"
	ActionChannelUpdate = "channel_update"
	ActionChannelSecret = "channel_secret"
	ActionChannelDelete = "channel_delete"
	// The protected Pi-hole groups changed; the detail lists those added and removed, by scope.
	ActionProtectedGroups = "protected_groups_update"
	// A warning to a channel's old destination (that it was changed, disabled or deleted) still failed after its
	// retries. Written by the app, as SystemUser, with who made the change.
	ActionNotificationFailed = "notification_failed"

	// Audit rows, or finished client reset runs, older than the retention were deleted; the detail has how many of
	// each and the cutoff. Written only when something was deleted.
	ActionAuditPrune = "audit_prune"
)

// SystemUser is the username on rows the app writes by itself, with no one acting, such as audit_prune.
const SystemUser = "(system)"

// Entry is one audit event.
type Entry struct {
	At           time.Time // zero means now
	UserID       int64     // 0 when there is no user row (a failed login with an unknown username)
	Username     string    // the acting user, or the username typed into a failed login
	Action       string
	Target       string // what the action was performed against, or ""
	InstanceID   int64  // 0 when the action isn't about one Pi-hole instance
	InstanceName string
	Err          error          // nil for success; its text is recorded as detail.error
	Detail       map[string]any // extra JSON detail; never secret values
	IP           string
}

// Result returns ResultSuccess or ResultFailure.
func (e Entry) Result() string {
	if e.Err != nil {
		return ResultFailure
	}
	return ResultSuccess
}

func (e Entry) detailJSON() (string, error) {
	d := make(map[string]any, len(e.Detail)+1)
	for k, v := range e.Detail {
		d[k] = v
	}
	if e.Err != nil {
		d["error"] = e.Err.Error()
	}
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("audit: detail: %w", err)
	}
	return string(b), nil
}

// tokenKey is the context key for the API token a request authenticated with.
type tokenKey struct{}

type tokenRef struct{ name, publicID string }

// WithToken records on ctx that the request authenticated with an API token, so that every audit row Insert writes
// for it says so (detail via_token and token_id), whichever code path writes the row.
func WithToken(ctx context.Context, name, publicID string) context.Context {
	return context.WithValue(ctx, tokenKey{}, tokenRef{name: name, publicID: publicID})
}

// Insert writes e to audit_log through q, normally the transaction that made the change. During a request made with
// an API token (see WithToken) the row's detail also carries via_token and token_id. The AUDIT line and
// notifications name the user as for any other request.
func Insert(ctx context.Context, q *db.Queries, e Entry) (int64, error) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if tok, ok := ctx.Value(tokenKey{}).(tokenRef); ok {
		d := make(map[string]any, len(e.Detail)+2)
		for k, v := range e.Detail {
			d[k] = v
		}
		d["via_token"], d["token_id"] = tok.name, tok.publicID
		e.Detail = d
	}
	detail, err := e.detailJSON()
	if err != nil {
		return 0, err
	}
	return q.InsertAudit(ctx, db.InsertAuditParams{
		At:           store.Millis(e.At),
		UserID:       sql.NullInt64{Int64: e.UserID, Valid: e.UserID != 0},
		Username:     e.Username,
		Action:       e.Action,
		Target:       e.Target,
		InstanceID:   sql.NullInt64{Int64: e.InstanceID, Valid: e.InstanceID != 0},
		InstanceName: e.InstanceName,
		Result:       e.Result(),
		Detail:       detail,
		Ip:           e.IP,
	})
}

// Logger writes AUDIT lines, and hands each entry to its sink (the notifier) once it is logged.
type Logger struct {
	l    *log.Logger
	sink atomic.Pointer[func(Entry)]
}

// SetSink sets a function that receives every entry Log writes, after its transaction has committed. It must not
// block: the notifier only queues. nil removes it.
func (l *Logger) SetSink(f func(Entry)) {
	if f == nil {
		l.sink.Store(nil)
		return
	}
	l.sink.Store(&f)
}

// NewLogger writes AUDIT lines to w, each prefixed with the UTC date and time.
func NewLogger(w io.Writer) *Logger {
	return &Logger{l: log.New(w, "", log.LstdFlags|log.LUTC)}
}

// Log writes one AUDIT line for e. Call it after the transaction that inserted e has committed.
//
// username, target and the error text are written with %q: any of them can contain attacker-controlled input (a
// login username, or an error that echoes it), and a raw newline would let that input forge extra AUDIT lines.
// action is always a constant from our own code, so it stays bare.
func (l *Logger) Log(e Entry) {
	if e.Err != nil {
		l.l.Printf("AUDIT user=%q action=%s target=%q result=failure error=%q", e.Username, e.Action, e.Target, e.Err.Error())
	} else {
		l.l.Printf("AUDIT user=%q action=%s target=%q result=success", e.Username, e.Action, e.Target)
	}
	if f := l.sink.Load(); f != nil {
		(*f)(e)
	}
}

// Record inserts e in its own transaction and logs it. It's for events that change nothing else in the database,
// such as a failed login.
func (l *Logger) Record(ctx context.Context, st *store.Store, e Entry) error {
	if err := st.WithTx(ctx, func(q *db.Queries) error {
		_, err := Insert(ctx, q, e)
		return err
	}); err != nil {
		return err
	}
	l.Log(e)
	return nil
}
