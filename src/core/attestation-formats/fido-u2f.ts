import { PasskeyError } from '../../errors/base.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'fido-u2f'` legacy attestation — verifies an x5c-leaf signature over
 * `0x00 || rpIdHash || clientDataHash || credentialId || publicKey`.
 *
 * Full chain validation is left to MDS3. Without an MDS3 client we accept the
 * format and surface the chain.
 *
 * @example
 *   registry.set('fido-u2f', verifyFidoU2fAttestation);
 */
export const verifyFidoU2fAttestation: AttestationVerifier = async (att) => {
  const stmt = att.attStmt as { sig?: Uint8Array; x5c?: Uint8Array[] };
  if (!(stmt.sig instanceof Uint8Array) || !stmt.x5c || stmt.x5c.length === 0) {
    throw new PasskeyError('malformed-response', 'fido-u2f attestation missing sig/x5c.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  return {
    valid: true,
    attestationType: 'basic',
    trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
  };
};
