import { InvalidAttestationError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'fido-u2f'` legacy attestation. The verifier accepts the format and
 * surfaces the trust chain; full chain validation is delegated to MDS3.
 *
 * Loaded via dynamic import (kept off the default bundle hot path).
 *
 * @example
 *   const { verifyFidoU2fAttestation } = await import('@authkit/passkeys/server/attestation/fido-u2f');
 */
export const verifyFidoU2fAttestation: AttestationVerifier = async (att) => {
  const stmt = att.attStmt as { sig?: Uint8Array; x5c?: Uint8Array[] };
  if (!(stmt.sig instanceof Uint8Array) || !stmt.x5c || stmt.x5c.length === 0) {
    throw new InvalidAttestationError('fido-u2f attestation missing sig/x5c.', {
      details: { reason: 'attestation_statement_invalid' },
    });
  }
  return {
    valid: true,
    attestationType: 'basic',
    trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
  };
};
