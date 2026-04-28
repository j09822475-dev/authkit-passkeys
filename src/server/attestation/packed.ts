import { InvalidAttestationError } from '../../errors/classes.js';
import { parseCoseKey } from '../../core/cose/key.js';
import { concatBytes } from '../../core/crypto/bytes.js';
import { verifySignature } from '../../core/crypto/verify.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'packed'` attestation — covers self-attestation and (when `x5c` is present)
 * basic / attCA attestation. Full x5c chain validation belongs to the MDS3
 * client; this verifier only checks the signature over
 * `authData || clientDataHash`.
 *
 * Shipped in the default server bundle.
 *
 * @example
 *   registry.set('packed', verifyPackedAttestation);
 */
export const verifyPackedAttestation: AttestationVerifier = async (att, ctx) => {
  const stmt = att.attStmt as { alg?: unknown; sig?: unknown; x5c?: unknown };
  if (typeof stmt.alg !== 'number' || !(stmt.sig instanceof Uint8Array)) {
    throw new InvalidAttestationError('packed attestation missing alg/sig.', {
      details: { reason: 'attestation_statement_invalid' },
    });
  }

  const signedData = concatBytes(att.rawAuthData, ctx.clientDataHash);

  if (stmt.x5c !== undefined) {
    if (!Array.isArray(stmt.x5c) || !stmt.x5c.every((c) => c instanceof Uint8Array)) {
      throw new InvalidAttestationError('packed attestation x5c is malformed.', {
        details: { reason: 'attestation_statement_invalid' },
      });
    }
    if (stmt.x5c.length > 0) {
      return {
        valid: true,
        attestationType: 'basic',
        trustChain: stmt.x5c.map((c) => Uint8Array.from(c as Uint8Array)),
      };
    }
  }

  if (!att.authData.attestedCredentialData) {
    throw new InvalidAttestationError('self-attestation requires attestedCredentialData.', {
      details: { reason: 'attestation_statement_invalid' },
    });
  }
  const coseKey = parseCoseKey(att.authData.attestedCredentialData.credentialPublicKey);
  if (coseKey.alg !== stmt.alg) {
    throw new InvalidAttestationError(
      `self-attestation alg mismatch: stmt=${stmt.alg}, key=${coseKey.alg}.`,
      { details: { reason: 'attestation_statement_invalid' } },
    );
  }
  const ok = await verifySignature(coseKey, stmt.sig, signedData);
  return { valid: ok, attestationType: 'self' };
};
