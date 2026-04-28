/// <reference types="node" />
/**
 * Node-only WebCrypto shim. The ONLY file in the package that imports
 * `node:crypto` — the `package.json#imports` `#webcrypto-shim` conditional
 * alias guarantees no other runtime ever resolves to it (PLAN §6.3 / §9.11).
 *
 * Node ≥18.17 also exposes `globalThis.crypto`, but we go through
 * `node:crypto`'s `webcrypto` export so the shim still loads under exotic
 * Node configurations where the global is not yet set (early v18.x patches
 * and some embedded Node builds).
 */
import { webcrypto as nodeWebcrypto } from 'node:crypto';

export const webcrypto: Crypto = nodeWebcrypto as unknown as Crypto;
export const subtle: SubtleCrypto = (nodeWebcrypto as unknown as Crypto).subtle;
