import { PasskeyInternalError } from '../../errors/internal.js';

/**
 * Cryptographically-secure random bytes via `crypto.getRandomValues`.
 *
 * @param length  Number of bytes to generate (1 ≤ length ≤ 65536).
 * @returns       A fresh `Uint8Array` of the requested length.
 * @throws {PasskeyInternalError}  When `length` is out of range or `crypto.getRandomValues` is unavailable.
 *
 * @example
 *   const challenge = randomBytes(32);   // 256-bit WebAuthn challenge
 */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 1 || length > 65536) {
    throw new PasskeyInternalError(`randomBytes: length must be 1..65536, got ${length}.`);
  }
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new PasskeyInternalError(
      'randomBytes: globalThis.crypto.getRandomValues is unavailable. ' +
        'Node 18+ exposes it natively; older runtimes need a polyfill.',
    );
  }
  return crypto.getRandomValues(new Uint8Array(length));
}
