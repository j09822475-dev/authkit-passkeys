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
import { subtle } from '#webcrypto-shim';

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

  return subtle.verify(algo.verifyParams, cryptoKey, sig, data);
}

/**
 * Fixed P-256 public-key JWK used to seed {@link dummyVerify}. The point is a
 * published RFC 7515 test vector — no private key is implied; a deterministic
 * value lets the import be cached so the unknown-credential branch does not
 * pay the cost of `crypto.subtle.generateKey` (which is orders of magnitude
 * slower than `subtle.verify` and would invert the timing-equalisation
 * promise from PLAN §9.10 / §9.14).
 */
const DUMMY_P256_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
  y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
  ext: true,
  key_ops: ['verify'],
};

let dummyVerifyKey: Promise<CryptoKey> | undefined;
function getDummyVerifyKey(): Promise<CryptoKey> {
  if (!dummyVerifyKey) {
    dummyVerifyKey = subtle.importKey(
      'jwk',
      DUMMY_P256_JWK,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );
  }
  return dummyVerifyKey;
}

/**
 * Constant-time-shape dummy verify. Run on the unknown-credential path so
 * authentication wall-clock time and error shape match the real
 * `verifySignature` branch (PLAN §9.10 / §9.14). Reuses a cached
 * `CryptoKey` so the per-request work is exactly one `subtle.verify` —
 * matching the verifying branch.
 *
 * @param data  The bytes that would have been verified.
 * @returns     Always `false`.
 */
export async function dummyVerify(data: Uint8Array): Promise<boolean> {
  const key = await getDummyVerifyKey();
  const fakeSig = new Uint8Array(64);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, fakeSig, data);
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
