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
	GroupLists         = "Lists and gravity"
	GroupLocalDNS      = "Local DNS"
	GroupDHCP          = "DHCP"
	GroupSchedules     = "Schedules"
	GroupTempClients   = "Temporary client changes"
	GroupInstances     = "Instances and groups"
	GroupAccess        = "Users, roles and LDAP"
	GroupSettings      = "Settings and system"
	GroupNotifications = "Notifications"
	GroupLogForwarding = "Log forwarding"
)

// actions lists every action an audit row can have, in the order a page shows them. TestActionsListed checks it
// against the constants in audit.go, so a new action can't be left out. instance_test isn't here: it only ever
// appears as the attempted action inside a permission_denied row.
var actions = []ActionInfo{
	{ActionLogin, GroupSignIn, "A login, or a failed attempt"},
	{ActionLogout, GroupSignIn, "A logout"},
	{ActionPasswordChange, GroupSignIn, "Someone changed their own password, or tried to"},
	{ActionTOTPEnable, GroupSignIn, "Someone turned two-factor login on"},
	{ActionTOTPDisable, GroupSignIn, "Someone turned their two-factor login off or tried to, or an admin removed a user's"},
	{ActionRecoveryCodeUsed, GroupSignIn, "A recovery code was used in place of a code from an authenticator app"},
	{ActionRecoveryCodesRegenerate, GroupSignIn, "Someone replaced their recovery codes, or tried to"},
	{ActionSessionRevoke, GroupSignIn, "A session was ended from the sessions page"},
	{ActionTokenCreate, GroupSignIn, "Someone made an API token"},
	{ActionTokenRevoke, GroupSignIn, "An API token was revoked by its owner or an admin"},
	{ActionTokenExpiredUse, GroupSignIn, "Something tried to use an API token that has expired"},
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
	{ActionPiholeGroupAdd, GroupPihole, "A Pi-hole group added"},
	{ActionPiholeGroupUpdate, GroupPihole, "A Pi-hole group renamed, or its comment changed"},
	{ActionPiholeGroupEnable, GroupPihole, "A Pi-hole group enabled"},
	{ActionPiholeGroupDisable, GroupPihole, "A Pi-hole group disabled, which changes blocking for every client in it"},
	{ActionPiholeGroupDelete, GroupPihole, "A Pi-hole group deleted, which takes it off every domain, client and list"},
	{ActionClientReset, GroupPihole, "Clients put back in their groups by a client reset, or a reset that failed"},
	{ActionGroupReconcile, GroupPihole, "A mirrored group's member made to match the primary"},

	{ActionListAdd, GroupLists, "A blocklist or allowlist subscribed to"},
	{ActionListUpdate, GroupLists, "A list's comment or groups changed, or the list enabled or disabled"},
	{ActionListDelete, GroupLists, "A list unsubscribed from"},
	{ActionGravityStart, GroupLists, "A gravity update started"},
	{ActionGravityRun, GroupLists, "A gravity update finished on an instance, or failed"},

	{ActionDNSRecordAdd, GroupLocalDNS, "A local DNS record added"},
	{ActionDNSRecordUpdate, GroupLocalDNS, "A local DNS record changed"},
	{ActionDNSRecordDelete, GroupLocalDNS, "A local DNS record deleted"},
	{ActionCNAMEAdd, GroupLocalDNS, "A CNAME added, which restarts DNS on the Pi-hole"},
	{ActionCNAMEUpdate, GroupLocalDNS, "A CNAME changed, which restarts DNS on the Pi-hole"},
	{ActionCNAMEDelete, GroupLocalDNS, "A CNAME deleted, which restarts DNS on the Pi-hole"},

	{ActionDHCPSettingsUpdate, GroupDHCP, "DHCP turned on or off, or its settings changed, which restarts DNS and DHCP on the Pi-hole"},
	{ActionDHCPStaticAdd, GroupDHCP, "A static DHCP lease added, which restarts DNS and DHCP on the Pi-hole"},
	{ActionDHCPStaticUpdate, GroupDHCP, "A static DHCP lease changed, which restarts DNS and DHCP on the Pi-hole"},
	{ActionDHCPStaticDelete, GroupDHCP, "A static DHCP lease deleted, which restarts DNS and DHCP on the Pi-hole"},
	{ActionDHCPLeaseDelete, GroupDHCP, "A DHCP lease deleted"},

	{ActionScheduleCreate, GroupSchedules, "A schedule added"},
	{ActionScheduleUpdate, GroupSchedules, "A schedule changed, or switched on or off"},
	{ActionScheduleDelete, GroupSchedules, "A schedule deleted"},
	{ActionScheduleRun, GroupSchedules, "A schedule turned blocking off or a Pi-hole group on or off, or failed to"},

	{ActionClientTempSet, GroupTempClients, "A client moved to other Pi-hole groups for a set time"},
	{ActionClientTempUpdate, GroupTempClients, "A temporary client change's end time changed"},
	{ActionClientTempEnd, GroupTempClients, "A temporary client change ended early, or its revert retried, by a person"},
	{ActionClientTempRevert, GroupTempClients, "A client put back in its groups when its time was up, or the revert failed"},

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
	{ActionUserTOTPPolicy, GroupAccess, "A user was required to use two-factor login, exempted from it, or left to their roles"},
	{ActionUserDisable, GroupAccess, "A user disabled"},
	{ActionUserEnable, GroupAccess, "A user enabled"},
	{ActionUserDelete, GroupAccess, "A user deleted"},
	{ActionUserPassword, GroupAccess, "An admin set a user's password"},
	{ActionRoleCreate, GroupAccess, "A role added"},
	{ActionRoleUpdate, GroupAccess, "A role renamed or described"},
	{ActionRoleTOTPUpdate, GroupAccess, "A role started or stopped requiring two-factor login"},
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
	{ActionLogDestCreate, GroupLogForwarding, "A log forwarding destination added"},
	{ActionLogDestUpdate, GroupLogForwarding, "A log forwarding destination changed, enabled or disabled"},
	{ActionLogDestDelete, GroupLogForwarding, "A log forwarding destination deleted"},
	{ActionLogDestFailed, GroupLogForwarding, "A log forwarding destination has been failing for five minutes, or a warning to its old place couldn't be delivered"},
	{ActionLogDestRecovered, GroupLogForwarding, "A log forwarding destination that had been failing works again"},
}

// Actions returns every action, grouped, in display order.
func Actions() []ActionInfo {
	return append([]ActionInfo(nil), actions...)
}
