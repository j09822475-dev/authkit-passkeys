import { PasskeyError } from '../../errors/base.js';
import { decodeCbor, type CborValue } from '../cose/cbor.js';
import type { ParsedAttestationObject } from '../../types/ceremony.js';
import { parseAuthenticatorData } from './auth-data.js';

/**
 * Parse a WebAuthn `attestationObject` (CBOR-encoded `{ fmt, authData, attStmt }`).
 *
 * The attestation statement (`attStmt`) is returned as-is — format-specific
 * verifiers in `core/attestation-formats/*` consume it.
 *
 * @param bytes  Raw attestation-object bytes (already base64url-decoded).
 * @returns      {@link ParsedAttestationObject}
 * @throws {PasskeyError}  Code `'malformed-response'` for malformed CBOR or missing keys.
 *
 * @example
 *   const att = parseAttestationObject(fromBase64Url(response.attestationObject));
 *   await verifyAttestation(att);
 */
export function parseAttestationObject(bytes: Uint8Array): ParsedAttestationObject {
  const { value } = decodeCbor(bytes);
  if (!(value instanceof Map)) {
    throw new PasskeyError('malformed-response', 'attestationObject is not a CBOR map.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }

  const fmtRaw = value.get('fmt');
  const authDataRaw = value.get('authData');
  const attStmtRaw = value.get('attStmt');

  if (typeof fmtRaw !== 'string') {
    throw new PasskeyError('malformed-response', 'attestationObject.fmt is missing or not a string.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  if (!(authDataRaw instanceof Uint8Array)) {
    throw new PasskeyError('malformed-response', 'attestationObject.authData is missing or not bytes.', {
      details: { reason: 'attestation-statement-invalid' },
    });
  }
  if (!(attStmtRaw instanceof Map)) {
    throw new PasskeyError('malformed-response', 'attestationObject.attStmt is missing or not a CBOR map.', {
      details: { reason: 'attestation-statement-invalid' },
    });
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
