// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Where the e2e server and its two app servers listen, for playwright.config.ts and the fixtures. Fixed, so baseURL
// is known before the server starts; change them here if they clash with something on your machine.
export const control = '127.0.0.1:18080';
export const fresh = '127.0.0.1:18081';
export const seeded = '127.0.0.1:18082';

export const stateURL = `http://${control}/state`;

// What the e2e server's fake Matrix homeserver has received, for the notifications tests; ?room=<room ID> narrows it.
export const matrixURL = `http://${control}/matrix`;
