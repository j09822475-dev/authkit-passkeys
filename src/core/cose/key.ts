import { PasskeyError } from '../../errors/base.js';
import { UnsupportedAlgorithmError } from '../../errors/classes.js';
import type { CoseAlgId } from '../../types/webauthn.js';
import type { ParsedCoseKey } from '../../types/parsed.js';
import { decodeCbor, type CborValue } from './cbor.js';
import { COSE_CURVE, coseAlgToWebCrypto } from './algorithms.js';

const KTY_OKP = 1;
const KTY_EC2 = 2;
const KTY_RSA = 3;

const KEY_KTY = 1;
const KEY_ALG = 3;
const KEY_EC_CRV = -1;
const KEY_EC_X = -2;
const KEY_EC_Y = -3;
const KEY_RSA_N = -1;
const KEY_RSA_E = -2;

/**
 * Parse a COSE_Key (RFC 8152) from raw CBOR bytes into a typed structure.
 *
 * Unknown map entries are ignored (per COSE rules). Unknown `kty` is rejected.
 *
 * @param cborBytes  Raw CBOR-encoded credential public key (from authenticator data).
 * @returns          {@link ParsedCoseKey}.
 * @throws {PasskeyError}  Code `'invalid_attestation'` for malformed CBOR or missing required fields.
 *
 * @example
 *   const cose = parseCoseKey(authData.attestedCredentialData!.credentialPublicKey);
 *   const key = await importCoseKey(cose);
 */
export function parseCoseKey(cborBytes: Uint8Array): ParsedCoseKey {
  const { value } = decodeCbor(cborBytes);
  if (!(value instanceof Map)) {
    throw bad('COSE key is not a CBOR map.');
  }

  const kty = num(value.get(KEY_KTY), 'COSE kty');
  const alg = num(value.get(KEY_ALG), 'COSE alg') as CoseAlgId;

  if (kty === KTY_EC2) {
    return {
      kty,
      alg,
      crv: num(value.get(KEY_EC_CRV), 'COSE crv'),
      x: bytes(value.get(KEY_EC_X), 'EC2 x'),
      y: bytes(value.get(KEY_EC_Y), 'EC2 y'),
    };
  }
  if (kty === KTY_OKP) {
    return {
      kty,
      alg,
      crv: num(value.get(KEY_EC_CRV), 'COSE crv'),
      x: bytes(value.get(KEY_EC_X), 'OKP x'),
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
  throw bad(`Unsupported COSE kty ${kty}.`);
}

/**
 * Import a parsed COSE key into a WebCrypto `CryptoKey` for signature
 * verification.
 *
 * RSA keys are imported via JWK so `n`/`e` leading-zero bytes are normalised;
 * EC2 keys are imported via JWK with `x`/`y` left-padded to the curve size;
 * OKP/Ed25519 keys are imported as `'raw'` 32-byte public keys.
 *
 * @param key  Parsed COSE key.
 * @returns    A WebCrypto verify-only `CryptoKey`.
 * @throws {UnsupportedAlgorithmError}  When the algorithm has no Web Crypto mapping.
 * @throws {PasskeyError}  Code `'invalid_attestation'` when required fields are missing.
 *
 * @example
 *   const key = await importCoseKey(parseCoseKey(rawCose));
 */
export async function importCoseKey(key: ParsedCoseKey): Promise<CryptoKey> {
  const algo = coseAlgToWebCrypto(key.alg);
  if (!algo) {
    throw new UnsupportedAlgorithmError(`COSE algorithm ${key.alg} is not supported by this build.`, {
      details: { reason: 'unsupported_algorithm', algorithm: key.alg },
    });
  }

  if (key.kty === KTY_RSA) {
    if (!key.n || !key.e) {
      throw bad('RSA COSE key is missing modulus or exponent.');
    }
    return crypto.subtle.importKey(
      'jwk',
      {
        kty: 'RSA',
        n: bytesToB64u(stripLeadingZeros(key.n)),
        e: bytesToB64u(stripLeadingZeros(key.e)),
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
      throw bad('EC2 COSE key is missing coordinates.');
    }
    const crvName = ec2CurveName(key.crv);
    const expectedLen = ec2CoordLen(key.crv);
    return crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: crvName,
        x: bytesToB64u(padLeft(key.x, expectedLen)),
        y: bytesToB64u(padLeft(key.y, expectedLen)),
        ext: true,
        key_ops: ['verify'],
      },
      algo.importParams,
      true,
      ['verify'],
    );
  }

  if (key.kty === KTY_OKP) {
    if (!key.x) throw bad('OKP COSE key is missing x.');
    if (key.crv !== COSE_CURVE.ED25519) {
      throw new UnsupportedAlgorithmError(`OKP curve ${key.crv} is not supported (only Ed25519).`, {
        details: { reason: 'unsupported_algorithm' },
      });
    }
    return crypto.subtle.importKey('raw', key.x, algo.importParams, true, ['verify']);
  }

  throw new UnsupportedAlgorithmError(`Unsupported COSE kty ${key.kty}.`, {
    details: { reason: 'unsupported_algorithm' },
  });
}

/**
 * Export a parsed COSE key as SPKI bytes (DER-encoded SubjectPublicKeyInfo).
 * Storage adapters persist the SPKI form so re-import on subsequent
 * authentications doesn't need to round-trip through COSE.
 *
 * @param key  Parsed COSE key.
 * @returns    SPKI bytes.
 */
export async function exportCoseKeyAsSpki(key: ParsedCoseKey): Promise<Uint8Array> {
  const cryptoKey = await importCoseKey(key);
  return new Uint8Array(await crypto.subtle.exportKey('spki', cryptoKey));
}

function ec2CurveName(crv: number | undefined): 'P-256' | 'P-384' | 'P-521' {
  switch (crv) {
    case COSE_CURVE.P_256:
      return 'P-256';
    case COSE_CURVE.P_384:
      return 'P-384';
    case COSE_CURVE.P_521:
      return 'P-521';
    default:
      throw bad(`Unknown EC2 curve ${crv}.`);
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
  if (b.length === len) return b;
  if (b.length > len) return b.subarray(b.length - len);
  const out = new Uint8Array(len);
  out.set(b, len - b.length);
  return out;
}

function stripLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

function bytesToB64u(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function num(value: CborValue | undefined, label: string): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  throw bad(`${label} is not a number.`);
}

function bytes(value: CborValue | undefined, label: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw bad(`${label} is not bytes.`);
}

function bad(msg: string): PasskeyError {
  return new PasskeyError('invalid_attestation', msg, {
    details: { reason: 'cose_key_parse_failed' },
  });
}
