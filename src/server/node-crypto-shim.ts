// Node-only WebCrypto availability shim.
//
// This is the SOLE module in the codebase that imports from `node:crypto`.
// Reached only via the `import` (Node) export condition; `workerd` /
// `edge-light` / `deno` / `browser` resolve to a separate `index.edge.js` that
// does not transitively import this file. The boundary is enforced by static
// imports — never a runtime `typeof process` guard, which bundlers would still
// include and edge runtimes would still reject.
//
// On Node 19+ `globalThis.crypto` is populated; on Node 18 we backfill from
// the `webcrypto` named export of `node:crypto`. This is a no-op on every
// other runtime that already exposes `globalThis.crypto`.

import { webcrypto } from 'node:crypto';

declare global {
  // eslint-disable-next-line no-var
  var crypto: Crypto;
}

if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.subtle === 'undefined') {
  // Node 18 LTS — `webcrypto` is structurally compatible with `globalThis.crypto`.
  globalThis.crypto = webcrypto as unknown as Crypto;
}
