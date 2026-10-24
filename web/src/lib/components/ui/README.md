<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Components from shadcn-svelte

The components in this folder were copied into the repository by the
[shadcn-svelte](https://github.com/huntabyte/shadcn-svelte) CLI (`npx shadcn-svelte add …`) and are MIT-licensed.
Their copyright and licence notice is in [LICENSE.md](LICENSE.md) and must stay with them. The same applies to
`src/lib/utils.ts`, which `shadcn-svelte init` wrote.

These files don't get pihole-rbac's AGPL SPDX header. They can be edited like our own code; a change made here is
ours, and the release's third-party notices list shadcn-svelte.

To add another component, from `web/`:

```sh
npm run check            # runs svelte-kit sync, which the CLI needs to read tsconfig.json
npx shadcn-svelte@latest add <component> --no-deps-install
npm install
```

`npm install <package>` deletes the file `svelte-kit sync` writes into `node_modules`, so the CLI is told not to
install dependencies itself, and `npm install` runs once it has finished.
