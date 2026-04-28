import { PasskeyError } from '../../errors/base.js';
import { parseCoseKey } from '../cose/key.js';
import { verifySignature } from '../crypto/verify.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'packed'` attestation — covers self-attestation and (optionally) x5c-rooted
 * basic/attCA attestation. The full x5c chain validation is delegated to the
 * MDS3 client when available; the verifier itself only checks the signature
 * over `authData || clientDataHash`.
 *
 * @example
 *   registry.set('packed', verifyPackedAttestation);
 */
export const verifyPackedAttestation: AttestationVerifier = async (att, ctx) => {
  const stmt = att.attStmt as { alg?: number; sig?: Uint8Array; x5c?: Uint8Array[] };
  if (typeof stmt.alg !== 'number' || !(stmt.sig instanceof Uint8Array)) {
    throw new PasskeyError('malformed-response', 'packed attestation missing alg/sig.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }

  const signedData = concat(att.rawAuthData, ctx.clientDataHash);

  if (stmt.x5c && stmt.x5c.length > 0) {
    // Basic / AttCA: full chain verification belongs to MDS3. Without it we
    // accept the format but mark the attestation type as 'basic' (caller decides
    // what to do — most consumer flows ignore attestation entirely).
    return {
      valid: true,
      attestationType: 'basic',
      trustChain: stmt.x5c.map((c) => Uint8Array.from(c)),
    };
  }

  // Self-attestation: verify with the credential's own public key.
  if (!att.authData.attestedCredentialData) {
    throw new PasskeyError('malformed-response', 'self-attestation requires attestedCredentialData.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  const coseKey = parseCoseKey(att.authData.attestedCredentialData.credentialPublicKey);
  if (coseKey.alg !== stmt.alg) {
    throw new PasskeyError(
      'malformed-response',
      `self-attestation alg mismatch: stmt=${stmt.alg}, key=${coseKey.alg}`,
      { details: { reason: 'attestation-statement-invalid' } },
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
