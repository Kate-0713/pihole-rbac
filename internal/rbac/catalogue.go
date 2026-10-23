// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rbac holds the permission catalogue, works out what a set of roles may do on which instance or group, and
// enforces the invariants on every change to roles, grants, user roles and LDAP mappings.
//
// Permissions are a fixed list in code. Roles are data: each grant gives a role one permission within a scope (all
// instances, one group or one instance). Access fails closed: anything not granted is refused, including permissions
// stored in the database that the catalogue no longer knows.
package rbac

import "slices"

// Permission names one thing a role can be allowed to do.
type Permission string

// The permission catalogue. A new permission also needs a migration that grants it to the builtin admin role; a test
// checks the two stay in step.
const (
	DomainsView     Permission = "domains.view"
	DomainsEdit     Permission = "domains.edit"
	ClientsView     Permission = "clients.view"
	ClientsEdit     Permission = "clients.edit"
	QueryLogView    Permission = "querylog.view"
	BlockingToggle  Permission = "blocking.toggle"
	DNSRestart      Permission = "dns.restart"
	ClientResetRun  Permission = "clientreset.run"
	DriftView       Permission = "drift.view"
	DriftReconcile  Permission = "drift.reconcile"
	InstancesManage Permission = "instances.manage"
	SettingsManage  Permission = "settings.manage"
	NotifyManage    Permission = "notifications.manage"
	UsersManage     Permission = "users.manage"
	RolesManage     Permission = "roles.manage"
	SessionsManage  Permission = "sessions.manage"
	AuditView       Permission = "audit.view"
	ConfigReload    Permission = "config.reload"
	AppUpdate       Permission = "app.update"
)

// Class says which scopes a permission can be granted at, and which targets it applies to.
type Class int

const (
	// ClassInstance permissions act on Pi-hole data. They can be granted at scope all, on any group or on one
	// instance, and checked against an instance or a mirrored group.
	ClassInstance Class = iota + 1
	// ClassGroup permissions only mean something for mirrored groups. They can be granted at scope all or on a
	// mirrored group, and checked against a mirrored group.
	ClassGroup
	// ClassGlobal permissions aren't about any instance. They can only be granted at scope all.
	ClassGlobal
)

func (c Class) String() string {
	switch c {
	case ClassInstance:
		return "instance"
	case ClassGroup:
		return "group"
	case ClassGlobal:
		return "global"
	}
	return "unknown"
}

// Info describes one permission in the catalogue.
type Info struct {
	Name        Permission
	Class       Class
	Description string
}

var catalogue = []Info{
	{DomainsView, ClassInstance, "List domains"},
	{DomainsEdit, ClassInstance, "Add and delete domains, edit their groups and comments"},
	{ClientsView, ClassInstance, "List clients"},
	{ClientsEdit, ClassInstance, "Edit client groups and comments"},
	{QueryLogView, ClassInstance, "View the query log"},
	{BlockingToggle, ClassInstance, "Enable or disable blocking"},
	{DNSRestart, ClassInstance, "Restart DNS"},
	{ClientResetRun, ClassInstance, "Run client reset manually"},
	{DriftView, ClassGroup, "View the drift report for a mirrored group"},
	{DriftReconcile, ClassGroup, "Reconcile a mirrored group"},
	{InstancesManage, ClassGlobal, "Add, edit and group instances"},
	{SettingsManage, ClassGlobal, "LDAP, client-reset schedule and general settings"},
	{NotifyManage, ClassGlobal, "Notification channels and rules"},
	{UsersManage, ClassGlobal, "Local users and their roles"},
	{RolesManage, ClassGlobal, "Roles, grants and LDAP group mappings"},
	{SessionsManage, ClassGlobal, "View and revoke other users' sessions"},
	{AuditView, ClassGlobal, "View the audit log"},
	{ConfigReload, ClassGlobal, "Reload secrets from the environment and files"},
	{AppUpdate, ClassGlobal, "Trigger updates and restart the app"},
}

var byName = func() map[Permission]Info {
	m := make(map[Permission]Info, len(catalogue))
	for _, p := range catalogue {
		m[p.Name] = p
	}
	return m
}()

// Catalogue returns every permission, in display order.
func Catalogue() []Info {
	return slices.Clone(catalogue)
}

// Lookup returns the catalogue entry for a permission name.
func Lookup(name string) (Info, bool) {
	p, ok := byName[Permission(name)]
	return p, ok
}

// Class returns the permission's class, or 0 if it isn't in the catalogue.
func (p Permission) Class() Class {
	return byName[p].Class
}

// Known reports whether the permission is in the catalogue.
func (p Permission) Known() bool {
	_, ok := byName[p]
	return ok
}
