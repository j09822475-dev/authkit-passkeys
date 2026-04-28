import { UnsupportedAlgorithmError } from '../../errors/classes.js';
import type { CoseAlgId } from '../../types/webauthn.js';
import type { ParsedCoseKey } from '../../types/parsed.js';
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
 * Web Crypto algorithm parameters and converts ECDSA DER signatures to the
 * raw `r||s` form Web Crypto expects.
 *
 * @param coseKey    The parsed COSE public key.
 * @param signature  Signature bytes as produced by the authenticator.
 * @param data       The signed bytes (typically `authenticatorData || sha256(clientDataJSON)`).
 * @returns          `true` iff the signature is valid.
 * @throws {UnsupportedAlgorithmError}  When the algorithm has no Web Crypto mapping.
 *
 * @example
 *   const ok = await verifySignature(cose, sig, signedData);
 */
export async function verifySignature(
  coseKey: ParsedCoseKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  const algo = coseAlgToWebCrypto(coseKey.alg);
  if (!algo) {
    throw new UnsupportedAlgorithmError(`Algorithm ${coseKey.alg} has no Web Crypto mapping.`, {
      details: { reason: 'unsupported_algorithm', algorithm: coseKey.alg },
    });
  }

  const cryptoKey = await importCoseKey(coseKey);
  const sig = isEcdsaAlg(coseKey.alg)
    ? derToRawEcdsa(signature, ec2ComponentLength(coseKey))
    : signature;

  return crypto.subtle.verify(algo.verifyParams, cryptoKey, sig, data);
}

/**
 * Constant-time-shape dummy verify. Run on the unknown-credential path so
 * authentication wall-clock time and error shape match a real failed verify
 * (PLAN §9.10 / §9.14).
 *
 * @param data  The bytes that would have been verified.
 * @returns     Always `false`.
 */
export async function dummyVerify(data: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  );
  const fakeSig = new Uint8Array(64);
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
      return key.alg === COSE_ALG.ES384 ? 48 : key.alg === COSE_ALG.ES512 ? 66 : 32;
  }
}

/**
 * Curve-aware ECDSA component length for an algorithm identifier. Used by
 * the authentication path where we have the alg but not a parsed key.
 */
export function ecdsaComponentLengthForAlg(alg: CoseAlgId): number {
  if (alg === COSE_ALG.ES384) return 48;
  if (alg === COSE_ALG.ES512) return 66;
  return 32;
}
