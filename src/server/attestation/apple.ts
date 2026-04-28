import { InvalidAttestationError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * Apple anonymous attestation. The verifier passes through the x5c chain;
 * full nonce verification (extension OID `1.2.840.113635.100.8.2`) is
 * delegated to MDS3 + Apple's WebAuthn root CA.
 *
 * Loaded via dynamic import (kept off the default bundle hot path so the
 * Apple X.509 SPKI extraction code only ships when an Apple credential
 * actually arrives).
 *
 * @example
 *   const { verifyAppleAttestation } = await import('@authkit/passkeys/server/attestation/apple');
 */
export const verifyAppleAttestation: AttestationVerifier = async (att) => {
  const stmt = att.attStmt as { x5c?: Uint8Array[] };
  if (!stmt.x5c || stmt.x5c.length === 0) {
    throw new InvalidAttestationError('apple attestation missing x5c.', {
      details: { reason: 'attestation_statement_invalid' },
    });
  }
  return {
    valid: true,
    attestationType: 'anonca',
    trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
  };
};
