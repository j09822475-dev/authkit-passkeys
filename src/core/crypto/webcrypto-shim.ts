/**
 * Default WebCrypto shim — used by the browser, Cloudflare Workers
 * (`workerd`), Vercel Edge (`edge-light`), Deno, and Bun. These runtimes
 * expose the WebCrypto API on `globalThis.crypto`, so the shim is a
 * one-liner.
 *
 * The Node-specific override lives in {@link ./webcrypto-shim.node.ts} and is
 * resolved exclusively via the `package.json#imports` `#webcrypto-shim`
 * conditional alias under the `node` condition. Runtime `typeof process`
 * guards are forbidden (PLAN §6.3 / §9.11) — esbuild-style bundlers still
 * inline the `node:crypto` import which breaks the Worker / edge bundles.
 */
export const webcrypto: Crypto = globalThis.crypto;
export const subtle: SubtleCrypto = globalThis.crypto.subtle;
