// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

// ActionInfo describes an action for people choosing which ones a notification channel receives.
type ActionInfo struct {
	Name        string
	Group       string
	Description string
}

// The groups actions are listed under.
const (
	GroupSignIn        = "Sign-in and sessions"
	GroupPihole        = "Pi-hole changes"
	GroupInstances     = "Instances and groups"
	GroupAccess        = "Users, roles and LDAP"
	GroupSettings      = "Settings and system"
	GroupNotifications = "Notifications"
)

// actions lists every action an audit row can have, in the order a page shows them. TestActionsListed checks it
// against the constants in audit.go, so a new action can't be left out. instance_test isn't here: it only ever
// appears as the attempted action inside a permission_denied row.
var actions = []ActionInfo{
	{ActionLogin, GroupSignIn, "A login, or a failed attempt"},
	{ActionLogout, GroupSignIn, "A logout"},
	{ActionPasswordChange, GroupSignIn, "Someone changed their own password, or tried to"},
	{ActionSessionRevoke, GroupSignIn, "A session was ended from the sessions page"},
	{ActionLDAPRecheck, GroupSignIn, "An LDAP user's roles changed, or their sessions ended, at a recheck"},
	{ActionPermissionDenied, GroupSignIn, "A change was refused for lack of a permission"},
	{ActionSetup, GroupSignIn, "First-run setup was completed, or a wrong setup token was tried"},
	{ActionSetupToken, GroupSignIn, "A new setup token was made on the command line"},
	{ActionResetAdmin, GroupSignIn, "An admin account was reset on the command line"},

	{ActionBlockingSet, GroupPihole, "Blocking turned on or off"},
	{ActionDNSRestart, GroupPihole, "DNS restarted"},
	{ActionDomainAdd, GroupPihole, "A domain added to a list"},
	{ActionDomainUpdate, GroupPihole, "A domain's groups or comment changed"},
	{ActionDomainDelete, GroupPihole, "A domain removed"},
	{ActionClientUpdate, GroupPihole, "A client's groups or comment changed"},
	{ActionClientReset, GroupPihole, "Clients put back in their groups by a client reset, or a reset that failed"},
	{ActionGroupReconcile, GroupPihole, "A mirrored group's member made to match the primary"},

	{ActionInstanceCreate, GroupInstances, "An instance added"},
	{ActionInstanceUpdate, GroupInstances, "An instance's settings changed"},
	{ActionInstanceEnable, GroupInstances, "An instance enabled"},
	{ActionInstanceDisable, GroupInstances, "An instance disabled"},
	{ActionInstanceDelete, GroupInstances, "An instance deleted"},
	{ActionInstancePassword, GroupInstances, "An instance's app password stored"},
	{ActionGroupCreate, GroupInstances, "An instance group added"},
	{ActionGroupUpdate, GroupInstances, "An instance group changed"},
	{ActionGroupDelete, GroupInstances, "An instance group deleted"},

	{ActionUserCreate, GroupAccess, "A local user added"},
	{ActionUserRoles, GroupAccess, "A user's roles changed"},
	{ActionUserDisable, GroupAccess, "A user disabled"},
	{ActionUserEnable, GroupAccess, "A user enabled"},
	{ActionUserDelete, GroupAccess, "A user deleted"},
	{ActionUserPassword, GroupAccess, "An admin set a user's password"},
	{ActionRoleCreate, GroupAccess, "A role added"},
	{ActionRoleUpdate, GroupAccess, "A role renamed or described"},
	{ActionRoleGrants, GroupAccess, "A role's permissions changed"},
	{ActionRoleDelete, GroupAccess, "A role deleted"},
	{ActionLDAPMappingAdd, GroupAccess, "An LDAP group mapped to a role"},
	{ActionLDAPMappingRemove, GroupAccess, "An LDAP group mapping removed"},
	{ActionLDAPMappingCheck, GroupAccess, "An LDAP group looked up in the directory"},

	{ActionSettingsUpdate, GroupSettings, "Settings changed (login methods, LDAP, sessions, audit retention)"},
	{ActionConfigReload, GroupSettings, "Secrets reloaded"},
	{ActionRotateKey, GroupSettings, "The master key was rotated on the command line"},
	{ActionAppRestart, GroupSettings, "The app was restarted"},
	{ActionUpdateRequest, GroupSettings, "An update was requested"},
	{ActionUpdateDone, GroupSettings, "An update finished and the new version is running"},
	{ActionUpdateFailed, GroupSettings, "An update failed before anything was replaced"},
	{ActionUpdateRolledBack, GroupSettings, "An update was rolled back because the new version didn't start"},
	{ActionAuditPrune, GroupSettings, "Old audit entries and client reset runs deleted"},
	{ActionClientResetRules, GroupSettings, "The client reset rules changed"},

	{ActionChannelCreate, GroupNotifications, "A notification channel added"},
	{ActionChannelUpdate, GroupNotifications, "A notification channel changed, enabled or disabled"},
	{ActionChannelSecret, GroupNotifications, "A notification channel's secret replaced"},
	{ActionChannelDelete, GroupNotifications, "A notification channel deleted"},
	{ActionProtectedGroups, GroupNotifications, "The protected Pi-hole groups changed"},
	{ActionNotificationFailed, GroupNotifications, "A warning to a channel's old destination couldn't be delivered"},
}

// Actions returns every action, grouped, in display order.
func Actions() []ActionInfo {
	return append([]ActionInfo(nil), actions...)
}
