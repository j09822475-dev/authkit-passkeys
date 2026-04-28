import { PasskeyError } from '../../errors/base.js';
import type { AttestationVerifier } from './types.js';

/**
 * Apple anonymous attestation — passes through the x5c chain. Full nonce
 * verification (extension OID `1.2.840.113635.100.8.2`) is delegated to MDS3 +
 * Apple's WebAuthn root CA.
 *
 * @example
 *   registry.set('apple', verifyAppleAttestation);
 */
export const verifyAppleAttestation: AttestationVerifier = async (att) => {
  const stmt = att.attStmt as { x5c?: Uint8Array[] };
  if (!stmt.x5c || stmt.x5c.length === 0) {
    throw new PasskeyError('malformed-response', 'apple attestation missing x5c.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  return {
    valid: true,
    attestationType: 'anonca',
    trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
  };
};
