// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError, api, unwrap } from '#lib/api/client.js';
import type { Channel, NotificationEvent } from '#lib/notifications.js';
import { can } from '#lib/permissions.js';
import type { PageLoad } from './$types';

// invalidate(_channelsKey) reads the list again, after a change.
export const _channelsKey = 'app:channels';

type Data = {
	channels: Channel[];
	events: NotificationEvent[];
	canStoreSecrets: boolean;
	error: string | null;
	allowed: boolean;
};

// The channels and the events they can receive, read in parallel.
export const load: PageLoad = async ({ parent, fetch, depends }): Promise<Data> => {
	depends(_channelsKey);
	await parent(); // the session must be known before can() is asked (see the instances page)
	const none = { channels: [], events: [], canStoreSecrets: false };
	if (!can('notifications.manage')) return { ...none, error: null, allowed: false };
	try {
		const [list, events] = await Promise.all([
			unwrap(api.GET('/api/v1/notifications/channels', { fetch })),
			unwrap(api.GET('/api/v1/notifications/events', { fetch }))
		]);
		return { channels: list.channels, events: events.events, canStoreSecrets: list.can_store_secrets, error: null, allowed: true };
	} catch (e) {
		if (e instanceof ApiError) return { ...none, error: e.message, allowed: true };
		throw e;
	}
};
