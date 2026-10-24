<!--
	SPDX-FileCopyrightText: 2026 Kate O'Grady
	SPDX-License-Identifier: AGPL-3.0-or-later
-->
<script lang="ts">
	// Importing a CSS file in the root layout is the SvelteKit way to load global styles: Vite bundles it into the
	// build, and every page sits inside this layout.
	import '../app.css';
	import favicon from '#lib/assets/favicon.svg';
	import type { LayoutProps } from './$types';

	// Svelte 5 runes: $props() is how a component receives its props. `data` is whatever +layout.ts's load returned (typed via the generated LayoutProps); `children` is the page being rendered inside this layout.
	let { data, children }: LayoutProps = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

{@render children()}

<!-- AGPL-3.0 section 13: every page, including login and setup, offers the source of the running build. Lives in the root layout so no page can forget it. -->
<footer>
	<a href={data.about.source_url} rel="noopener noreferrer">Source code</a> · {data.about.license}
</footer>
