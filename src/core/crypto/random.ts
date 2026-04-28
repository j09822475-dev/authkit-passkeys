import { InternalError } from '../../errors/classes.js';
import { webcrypto } from '#webcrypto-shim';

/**
 * Cryptographically-secure random bytes via `crypto.getRandomValues`.
 *
 * Single source of randomness in the library — every challenge, signing-key
 * `kid`, and replay-protection nonce ultimately comes from here.
 *
 * @param length  Number of bytes to generate (1 ≤ length ≤ 65536).
 * @returns       A fresh `Uint8Array` of the requested length.
 * @throws {InternalError}  When `length` is out of range or
 *                          `crypto.getRandomValues` is unavailable.
 *
 * @example
 *   const challenge = randomBytes(32); // 256-bit WebAuthn challenge
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 65536) {
    throw new InternalError(`randomBytes: length must be 1..65536, got ${length}.`);
  }
  if (!webcrypto || typeof webcrypto.getRandomValues !== 'function') {
    throw new InternalError(
      'randomBytes: WebCrypto getRandomValues is unavailable. ' +
        'Node 18+ exposes it natively; older runtimes need a polyfill.',
    );
  }
  return webcrypto.getRandomValues(new Uint8Array(length));
}
