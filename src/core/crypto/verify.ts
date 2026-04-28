import { PasskeyError } from '../../errors/base.js';
import type { ParsedCoseKey } from '../../types/ceremony.js';
import {
  COSE_ALG,
  COSE_CURVE,
  coseAlgToWebCrypto,
  isEcdsaAlg,
} from '../cose/algorithms.js';
import { importCoseKey } from '../cose/key.js';
import { derToRawEcdsa } from './der.js';

/**
 * Verify a signature against a parsed COSE key. Dispatches to the correct
 * Web Crypto algorithm parameters and converts ECDSA DER signatures to the raw
 * `r||s` form Web Crypto expects.
 *
 * @param coseKey    The parsed COSE public key (from authenticator data).
 * @param signature  Signature bytes as produced by the authenticator.
 * @param data       The signed bytes (typically `authenticatorData || sha256(clientDataJSON)`).
 * @returns          `true` if the signature is valid, otherwise `false`.
 * @throws {PasskeyError}  Code `'unsupported-attestation-format'` when the algorithm has no Web Crypto mapping.
 *
 * @example
 *   const ok = await verifySignature(cose, sig, signedData);
 *   if (!ok) return err(new PasskeyVerificationError('authentication-failed'));
 */
export async function verifySignature(
  coseKey: ParsedCoseKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const algo = coseAlgToWebCrypto(coseKey.alg);
  if (!algo) {
    throw new PasskeyError(
      'unsupported-attestation-format',
      `Algorithm ${coseKey.alg} has no Web Crypto mapping.`,
      { details: { reason: 'unsupported-algorithm', algorithm: coseKey.alg } },
    );
  }

  const cryptoKey = await importCoseKey(coseKey);
  const sig = isEcdsaAlg(coseKey.alg)
    ? derToRawEcdsa(signature, ec2ComponentLength(coseKey))
    : signature;

  return crypto.subtle.verify(algo.verifyParams, cryptoKey, sig, data);
}

/**
 * Constant-time-shape dummy verify. Used on the `unknown-credential` path so
 * the authentication response time and error shape match a real failed verify
 * — see PLAN §9.10.
 *
 * @param data  The bytes that would have been verified.
 * @returns     Always `false`.
 */
export async function dummyVerify(data: Uint8Array): Promise<boolean> {
  // Generate a throw-away P-256 key to feed Web Crypto a real verify call.
  const key = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  );
  const fakeSig = new Uint8Array(64); // 32-byte r || 32-byte s zeros
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.publicKey, fakeSig, data);
}

function ec2ComponentLength(key: ParsedCoseKey): number {
  switch (key.crv) {
    case COSE_CURVE.P_256:
      return 32;
    case COSE_CURVE.P_384:
      return 48;
    case COSE_CURVE.P_521:
      return 66;
    default:
      // Sensible default; only reached with malformed keys (alg ES256 implies P-256).
      return key.alg === COSE_ALG.ES384 ? 48 : key.alg === COSE_ALG.ES512 ? 66 : 32;
  }
}
