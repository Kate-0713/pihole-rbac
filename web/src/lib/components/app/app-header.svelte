<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	import ChevronDownIcon from '@lucide/svelte/icons/chevron-down';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { Button, buttonVariants } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { can, canAny, canAnyGlobal } from '#lib/permissions.js';
	import { notices } from '#lib/stores/notices.svelte.js';
	import { session } from '#lib/stores/session.svelte.js';
	import { usesTarget, withTarget } from '#lib/stores/targets.svelte.js';
	import { cn } from '#lib/utils.js';
	import ChangePasswordDialog from './change-password-dialog.svelte';
	import TargetPicker from './target-picker.svelte';

	let { target }: { target: string | null } = $props();

	// The nav only offers what the user can do on the selected target; the server checks again on every request.
	// $derived.by takes a function, for values that need more than one expression to work out.
	let pages = $derived.by(() =>
		[
			{ href: '/dashboard', label: 'Dashboard', show: canAny(target) },
			{ href: '/domains', label: 'Domains', show: can('domains.view', target) },
			{ href: '/clients', label: 'Clients', show: can('clients.view', target) },
			{ href: '/querylog', label: 'Query log', show: can('querylog.view', target) },
			// Only a mirrored group has drift.
			{ href: '/drift', label: 'Drift', show: !!target?.startsWith('g-') && can('drift.view', target) }
		].filter((p) => p.show)
	);

	let adminPages = $derived(
		[
			{ href: '/admin/instances', label: 'Instances', show: can('instances.manage') },
			{ href: '/admin/groups', label: 'Groups', show: can('instances.manage') },
			{ href: '/admin/users', label: 'Users', show: can('users.manage') },
			{ href: '/admin/roles', label: 'Roles', show: can('roles.manage') },
			{ href: '/admin/ldap', label: 'LDAP', show: canAnyGlobal('roles.manage', 'settings.manage') },
			{ href: '/admin/sessions', label: 'Sessions', show: can('sessions.manage') },
			{ href: '/admin/notifications', label: 'Notifications', show: can('notifications.manage') },
			{ href: '/admin/audit', label: 'Audit log', show: can('audit.view') },
			{ href: '/admin/client-reset', label: 'Client reset', show: can('settings.manage') },
			{ href: '/admin/settings', label: 'Settings', show: can('settings.manage') },
			{ href: '/admin/system', label: 'System', show: canAnyGlobal('config.reload', 'app.update') }
		].filter((p) => p.show)
	);

	// `page` from $app/state is reactive, so the highlighted link follows navigation.
	const isCurrent = (href: string) => page.url.pathname === href || page.url.pathname.startsWith(href + '/');

	let passwordOpen = $state(false);
	let loggingOut = $state(false);
	async function logout() {
		loggingOut = true;
		try {
			await session.logout();
			await goto('/login', { replace: true });
		} catch (e) {
			notices.error(e, "Couldn't log out");
		} finally {
			loggingOut = false;
		}
	}
</script>

<header class="border-b">
	<div class="mx-auto flex max-w-6xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
		<a href={withTarget('/dashboard', target)} class="font-semibold">pihole-rbac</a>

		<nav aria-label="Main" class="flex flex-wrap items-center gap-1">
			{#each pages as p (p.href)}
				<a
					href={withTarget(p.href, target)}
					aria-current={isCurrent(p.href) ? 'page' : undefined}
					class={cn(
						buttonVariants({ variant: 'ghost', size: 'sm' }),
						isCurrent(p.href) && 'bg-accent text-accent-foreground'
					)}>{p.label}</a
				>
			{/each}

			{#if adminPages.length > 0}
				<DropdownMenu.Root>
					<!-- bits-ui's `child` snippet hands the trigger's props to our own element, so the menu opens from a
					     styled Button instead of bits-ui's default element. -->
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Button
								{...props}
								variant="ghost"
								size="sm"
								class={cn(isCurrent('/admin') && 'bg-accent text-accent-foreground')}
							>
								Admin <ChevronDownIcon />
							</Button>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="start">
						{#each adminPages as p (p.href)}
							<DropdownMenu.Item>
								{#snippet child({ props })}
									<!-- A real link, so middle-click and "open in new tab" work. -->
									<a {...props} href={p.href}>{p.label}</a>
								{/snippet}
							</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			{/if}
		</nav>

		<div class="ml-auto flex items-center gap-2">
			<!-- Admin pages don't act on an instance, so there's nothing to pick there. -->
			{#if usesTarget(page.url.pathname)}
				<TargetPicker current={target} />
			{/if}

			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="outline" size="sm" aria-label="Account: {session.user?.username}">
							{session.user?.username}
							<ChevronDownIcon />
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content align="end">
					<DropdownMenu.Label class="text-muted-foreground text-xs font-normal">
						{session.user?.source === 'ldap' ? 'Directory account' : 'Local account'}
					</DropdownMenu.Label>
					<DropdownMenu.Separator />
					<!-- An LDAP user's password lives in the directory, so only local accounts can change it here. -->
					<DropdownMenu.Item>
						{#snippet child({ props })}
							<a {...props} href="/account/sessions">Your sessions</a>
						{/snippet}
					</DropdownMenu.Item>
					{#if session.user?.source === 'local'}
						<DropdownMenu.Item onSelect={() => (passwordOpen = true)}>Change password</DropdownMenu.Item>
					{/if}
					<DropdownMenu.Item disabled={loggingOut} onSelect={logout}>Log out</DropdownMenu.Item>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		</div>
	</div>
</header>

<ChangePasswordDialog bind:open={passwordOpen} />
