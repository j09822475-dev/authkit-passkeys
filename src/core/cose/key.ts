import { PasskeyError } from '../../errors/base.js';
import type { COSEAlgorithmIdentifier } from '../../types/webauthn-json.js';
import type { ParsedCoseKey } from '../../types/ceremony.js';
import { decodeCbor, type CborValue } from './cbor.js';
import { COSE_ALG, COSE_CURVE, coseAlgToWebCrypto } from './algorithms.js';

const KTY_OKP = 1;
const KTY_EC2 = 2;
const KTY_RSA = 3;

const KEY_KTY = 1;
const KEY_ALG = 3;
const KEY_CRV = -1;
const KEY_X = -2;
const KEY_Y = -3;
const KEY_RSA_N = -1;
const KEY_RSA_E = -2;

/**
 * Parse a COSE_Key (RFC 8152) from raw CBOR bytes into a typed structure.
 *
 * @param cborBytes  Raw CBOR-encoded credential public key (from authenticator data).
 * @returns          {@link ParsedCoseKey} — typed representation suitable for SPKI export.
 * @throws {PasskeyError}  Code `'malformed-response'` for malformed CBOR or missing required fields.
 *
 * @example
 *   const cose = parseCoseKey(authData.attestedCredentialData.credentialPublicKey);
 *   const cryptoKey = await importCoseKey(cose);
 */
export function parseCoseKey(cborBytes: Uint8Array): ParsedCoseKey {
  const { value } = decodeCbor(cborBytes);
  if (!(value instanceof Map)) {
    throw new PasskeyError('malformed-response', 'COSE key is not a CBOR map.', {
      details: { reason: 'cose-key-parse-failed' },
    });
  }

  const kty = num(value.get(KEY_KTY), 'COSE kty');
  const alg = num(value.get(KEY_ALG), 'COSE alg') as COSEAlgorithmIdentifier;

  if (kty === KTY_EC2) {
    return {
      kty,
      alg,
      crv: num(value.get(KEY_CRV), 'COSE crv'),
      x: bytes(value.get(KEY_X), 'EC2 x'),
      y: bytes(value.get(KEY_Y), 'EC2 y'),
    };
  }
  if (kty === KTY_OKP) {
    return {
      kty,
      alg,
      crv: num(value.get(KEY_CRV), 'COSE crv'),
      x: bytes(value.get(KEY_X), 'OKP x'),
    };
  }
  if (kty === KTY_RSA) {
    return {
      kty,
      alg,
      n: bytes(value.get(KEY_RSA_N), 'RSA n'),
      e: bytes(value.get(KEY_RSA_E), 'RSA e'),
    };
  }
  throw new PasskeyError('malformed-response', `Unsupported COSE kty ${kty}.`, {
    details: { reason: 'cose-key-parse-failed' },
  });
}

/**
 * Import a parsed COSE key into a WebCrypto `CryptoKey` for signature verification.
 *
 * For EC2/OKP keys we synthesize SPKI bytes; for RSA we use JWK directly.
 *
 * @param key  Parsed COSE key.
 * @returns    A WebCrypto verify-only `CryptoKey`.
 * @throws {PasskeyError}  Code `'unsupported-attestation-format'` (with `reason: 'unsupported-algorithm'`)
 *                        when the algorithm has no WebCrypto mapping.
 *
 * @example
 *   const cose = parseCoseKey(rawCose);
 *   const key = await importCoseKey(cose);
 *   const ok = await crypto.subtle.verify(verifyParams, key, signature, signedData);
 */
export async function importCoseKey(key: ParsedCoseKey): Promise<CryptoKey> {
  const algo = coseAlgToWebCrypto(key.alg);
  if (!algo) {
    throw new PasskeyError(
      'unsupported-attestation-format',
      `COSE algorithm ${key.alg} is not supported by this build.`,
      { details: { reason: 'unsupported-algorithm', algorithm: key.alg } },
    );
  }

  if (key.kty === KTY_RSA) {
    if (!key.n || !key.e) {
      throw new PasskeyError('malformed-response', 'RSA COSE key missing modulus or exponent.', {
        details: { reason: 'cose-key-parse-failed' },
      });
    }
    return crypto.subtle.importKey(
      'jwk',
      {
        kty: 'RSA',
        n: bytesToBase64Url(stripLeadingZeros(key.n)),
        e: bytesToBase64Url(stripLeadingZeros(key.e)),
        ext: true,
        key_ops: ['verify'],
      },
      algo.importParams,
      true,
      ['verify'],
    );
  }

  if (key.kty === KTY_EC2) {
    if (!key.x || !key.y) {
      throw new PasskeyError('malformed-response', 'EC2 COSE key missing coordinates.', {
        details: { reason: 'cose-key-parse-failed' },
      });
    }
    const crvName = ec2CurveName(key.crv);
    const expectedLen = ec2CoordLen(key.crv);
    return crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: crvName,
        x: bytesToBase64Url(padLeft(key.x, expectedLen)),
        y: bytesToBase64Url(padLeft(key.y, expectedLen)),
        ext: true,
        key_ops: ['verify'],
      },
      algo.importParams,
      true,
      ['verify'],
    );
  }

  if (key.kty === KTY_OKP) {
    if (!key.x) {
      throw new PasskeyError('malformed-response', 'OKP COSE key missing x.', {
        details: { reason: 'cose-key-parse-failed' },
      });
    }
    if (key.crv !== COSE_CURVE.ED25519) {
      throw new PasskeyError(
        'unsupported-attestation-format',
        `OKP curve ${key.crv} not supported (only Ed25519).`,
        { details: { reason: 'unsupported-algorithm' } },
      );
    }
    // Web Crypto Ed25519 (Level 3) imports raw 32-byte public key directly.
    return crypto.subtle.importKey('raw', key.x, algo.importParams, true, ['verify']);
  }

  throw new PasskeyError(
    'unsupported-attestation-format',
    `Unsupported COSE kty ${key.kty}.`,
    { details: { reason: 'unsupported-algorithm' } },
  );
}

/**
 * Export a parsed COSE key as SPKI bytes (DER-encoded SubjectPublicKeyInfo).
 *
 * @param key  Parsed COSE key.
 * @returns    SPKI bytes — store on `CredentialRecord.publicKey`.
 * @throws {PasskeyError}  When the key cannot be re-exported (e.g. unsupported alg).
 */
export async function exportCoseKeyAsSpki(key: ParsedCoseKey): Promise<Uint8Array> {
  const cryptoKey = await importCoseKey(key);
  const spki = await crypto.subtle.exportKey('spki', cryptoKey);
  return new Uint8Array(spki);
}

/** Curve identifier → JWK curve name. */
function ec2CurveName(crv: number | undefined): 'P-256' | 'P-384' | 'P-521' {
  switch (crv) {
    case COSE_CURVE.P_256:
      return 'P-256';
    case COSE_CURVE.P_384:
      return 'P-384';
    case COSE_CURVE.P_521:
      return 'P-521';
    default:
      throw new PasskeyError('malformed-response', `Unknown EC2 curve ${crv}.`, {
        details: { reason: 'cose-key-parse-failed' },
      });
  }
}

function ec2CoordLen(crv: number | undefined): number {
  switch (crv) {
    case COSE_CURVE.P_256:
      return 32;
    case COSE_CURVE.P_384:
      return 48;
    case COSE_CURVE.P_521:
      return 66;
    default:
      return 32;
  }
}

function padLeft(b: Uint8Array, len: number): Uint8Array {
  if (b.length >= len) return b.length === len ? b : b.subarray(b.length - len);
  const out = new Uint8Array(len);
  out.set(b, len - b.length);
  return out;
}

function stripLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function bytesToBase64Url(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function num(value: CborValue | undefined, label: string): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  throw new PasskeyError('malformed-response', `${label} is not a number.`, {
    details: { reason: 'cose-key-parse-failed' },
  });
}

function bytes(value: CborValue | undefined, label: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new PasskeyError('malformed-response', `${label} is not bytes.`, {
    details: { reason: 'cose-key-parse-failed' },
  });
}

// Re-export for convenience to keep imports tidy in the verifier.
export { COSE_ALG };
