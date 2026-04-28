import { InvalidAttestationError } from '../../errors/classes.js';
import { parseCoseKey } from '../../core/cose/key.js';
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
  const stmt = att.attStmt as { alg?: number; sig?: Uint8Array; x5c?: Uint8Array[] };
  if (typeof stmt.alg !== 'number' || !(stmt.sig instanceof Uint8Array)) {
    throw new InvalidAttestationError('packed attestation missing alg/sig.', {
      details: { reason: 'attestation_statement_invalid' },
    });
  }

  const signedData = concat(att.rawAuthData, ctx.clientDataHash);

  if (stmt.x5c && stmt.x5c.length > 0) {
    return {
      valid: true,
      attestationType: 'basic',
      trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
    };
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

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
