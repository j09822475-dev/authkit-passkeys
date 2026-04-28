import { PasskeyError } from '../../errors/base.js';
import type { Base64Url } from '../../types/webauthn.js';

const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

/**
 * Encode a `Uint8Array` to a padding-omitted base64url string. Pure ASCII
 * output — works in every JS runtime without `Buffer`.
 *
 * @param bytes  Byte array to encode.
 * @returns      Branded base64url string (no trailing `=`).
 *
 * @example
 *   const challenge = toBase64Url(randomBytes(32));
 */
export function toBase64Url(bytes: Uint8Array): Base64Url {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i] as number);
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') as Base64Url;
}

/**
 * Decode a base64url string (with or without `=` padding) to bytes. Accepts
 * the standard base64 alphabet (`+/`) for compatibility, but rejects every
 * other character.
 *
 * @param input  base64url string.
 * @returns      Decoded byte array.
 * @throws {PasskeyError}  Code `'invalid_attestation'` (reason `'challenge_malformed'`)
 *                         when the input contains illegal characters.
 *
 * @example
 *   fromBase64Url('AQID') // Uint8Array([1, 2, 3])
 */
export function fromBase64Url(input: string): Uint8Array {
  const stripped = input.replace(/=+$/, '');
  const normalized = stripped.replace(/\+/g, '-').replace(/\//g, '_');
  if (!BASE64URL_RE.test(normalized)) {
    throw new PasskeyError('invalid_attestation', 'Input is not valid base64url.', {
      details: { reason: 'challenge_malformed' },
    });
  }
  const padded = normalized.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const s = atob(padded + '='.repeat(padLen));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Validate a string against the base64url alphabet and brand it as
 * {@link Base64Url}. Intended for narrowing untrusted input from the wire
 * (response.id, response.rawId, etc.) before it's passed into anything that
 * expects the branded type.
 *
 * @param input  Candidate string.
 * @returns      The same string, branded.
 * @throws {PasskeyError}  Code `'invalid_attestation'` when the input is not valid base64url.
 */
export function assertBase64Url(input: string): Base64Url {
  const stripped = input.replace(/=+$/, '');
  const normalized = stripped.replace(/\+/g, '-').replace(/\//g, '_');
  if (!BASE64URL_RE.test(normalized)) {
    throw new PasskeyError('invalid_attestation', 'String is not valid base64url.');
  }
  return input as Base64Url;
}

/**
 * Convenience: convert a UTF-8 string to a base64url-encoded form.
 *
 * @param str  UTF-8 input.
 * @returns    base64url-encoded UTF-8 bytes.
 */
export function utf8ToBase64Url(str: string): Base64Url {
  return toBase64Url(new TextEncoder().encode(str));
}

/**
 * Convenience: decode a base64url string and interpret the bytes as UTF-8.
 *
 * @param input  base64url input.
 * @returns      Decoded UTF-8 string.
 * @throws {PasskeyError}  When the input is not valid base64url or not valid UTF-8.
 */
export function base64UrlToUtf8(input: string): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(fromBase64Url(input));
}
