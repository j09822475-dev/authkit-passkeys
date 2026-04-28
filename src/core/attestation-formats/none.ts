import type { ParsedAttestationObject } from '../../types/ceremony.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'none'` attestation format — trivially valid. Most consumer flows (Apple
 * passkeys, Google PM, etc.) use this format because they don't ship
 * device-attestation certificates by default.
 *
 * @example
 *   registry.set('none', verifyNoneAttestation);
 */
export const verifyNoneAttestation: AttestationVerifier = async (_att: ParsedAttestationObject) => {
  return { valid: true, attestationType: 'none' };
};
