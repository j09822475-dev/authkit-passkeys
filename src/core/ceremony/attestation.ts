import { PasskeyError } from '../../errors/base.js';
import { decodeCbor, type CborValue } from '../cose/cbor.js';
import type { ParsedAttestationObject } from '../../types/parsed.js';
import { parseAuthenticatorData } from './auth-data.js';

/**
 * Parse a WebAuthn `attestationObject` (CBOR-encoded `{ fmt, authData, attStmt }`).
 *
 * The attestation statement (`attStmt`) is returned as a string-keyed object —
 * format-specific verifiers in `core/attestation-formats/*` consume it. Keys
 * with non-string CBOR labels are dropped (none of the supported formats use
 * non-string labels).
 *
 * @param bytes  Raw attestation-object bytes (already base64url-decoded).
 * @returns      {@link ParsedAttestationObject}.
 * @throws {PasskeyError}  Code `'invalid_attestation'` for malformed CBOR / missing keys.
 *
 * @example
 *   const att = parseAttestationObject(fromBase64Url(response.response.attestationObject));
 */
export function parseAttestationObject(bytes: Uint8Array): ParsedAttestationObject {
  const { value } = decodeCbor(bytes);
  if (!(value instanceof Map)) {
    throw bad('attestationObject is not a CBOR map.');
  }

  const fmtRaw = value.get('fmt');
  const authDataRaw = value.get('authData');
  const attStmtRaw = value.get('attStmt');

  if (typeof fmtRaw !== 'string') {
    throw bad('attestationObject.fmt is missing or not a string.');
  }
  if (!(authDataRaw instanceof Uint8Array)) {
    throw bad('attestationObject.authData is missing or not bytes.');
  }
  if (!(attStmtRaw instanceof Map)) {
    throw bad('attestationObject.attStmt is missing or not a CBOR map.');
  }

  const authData = parseAuthenticatorData(authDataRaw);
  return {
    fmt: fmtRaw,
    authData,
    attStmt: cborMapToObject(attStmtRaw),
    rawAuthData: authDataRaw,
  };
}

function cborMapToObject(map: Map<CborValue, CborValue>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of map.entries()) {
    if (typeof k === 'string') out[k] = v;
  }
  return out;
}

function bad(msg: string): PasskeyError {
  return new PasskeyError('invalid_attestation', msg, {
    details: { reason: 'attestation_statement_invalid' },
  });
}
