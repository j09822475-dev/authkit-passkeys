import { PasskeyError } from '../../errors/base.js';

const BASE64URL_RE = /^[A-Za-z0-9_-]*=*$/;

/**
 * Encode a `Uint8Array` to a padded-omitted base64url string. Pure ASCII output
 * — works in every JS runtime without `Buffer`.
 *
 * @param bytes  Byte array to encode.
 * @returns      base64url string without trailing `=`.
 * @example      toBase64Url(new Uint8Array([1,2,3])) // "AQID"
 */
export function toBase64Url(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i] as number);
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode a base64url string (with or without padding) to bytes.
 *
 * @param input  base64url string. Accepts both `+/` and `-_` alphabets.
 * @returns      Decoded byte array.
 * @throws {PasskeyError}  Code `'malformed-response'` when the input contains illegal characters.
 * @example      fromBase64Url("AQID") // Uint8Array([1,2,3])
 */
export function fromBase64Url(input: string): Uint8Array {
  if (!BASE64URL_RE.test(input.replace(/\+/g, '-').replace(/\//g, '_'))) {
    throw new PasskeyError('malformed-response', 'Input is not valid base64url.');
  }
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const s = atob(padded + '='.repeat(padLen));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Convenience: convert a UTF-8 string to base64url bytes.
 *
 * @param str  UTF-8 input.
 * @returns    base64url-encoded UTF-8 bytes.
 */
export function utf8ToBase64Url(str: string): string {
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
