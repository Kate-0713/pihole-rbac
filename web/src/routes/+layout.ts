// Page options for every route (they cascade from the root layout).
// ssr = false: render only in the browser; the Go binary has no JS runtime.
// prerender = false: nothing is built ahead of time; adapter-static's
// fallback page (index.html) boots the app for every URL.
export const ssr = false;
export const prerender = false;
