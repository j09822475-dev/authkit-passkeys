import type { AttestationVerifier } from './types.js';

/**
 * `'none'` attestation — trivially valid. Most consumer flows (Apple
 * passkeys, Google PM, etc.) use this format because they don't ship
 * device-attestation certificates by default.
 *
 * Shipped in the default server bundle.
 *
 * @example
 *   registry.set('none', verifyNoneAttestation);
 */
export const verifyNoneAttestation: AttestationVerifier = async () => {
  return { valid: true, attestationType: 'none' };
};
