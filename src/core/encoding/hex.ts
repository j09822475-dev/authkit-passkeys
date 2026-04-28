import { InternalError } from '../../errors/classes.js';
import type { AaguidString } from '../../types/webauthn.js';

/**
 * Encode bytes as a lower-case hexadecimal string.
 *
 * @param bytes  Input bytes.
 * @returns      Hex string (length = 2 × bytes.length).
 *
 * @example
 *   toHex(new Uint8Array([0xab, 0x01])) // 'ab01'
 */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return s;
}

/**
 * Decode a hex string (any case, optional `0x` prefix). Strict — rejects
 * odd-length and non-hex characters.
 *
 * @param input  Hex string.
 * @returns      Decoded bytes.
 * @throws {InternalError}  When the input has an odd length or non-hex characters.
 *
 * @example
 *   fromHex('ab01') // Uint8Array([0xab, 0x01])
 */
export function fromHex(input: string): Uint8Array {
  const s = input.startsWith('0x') ? input.slice(2) : input;
  if (s.length % 2 !== 0) {
    throw new InternalError('Hex string has odd length.');
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new InternalError(`Invalid hex character at offset ${i * 2}.`);
    out[i] = byte;
  }
  return out;
}

/**
 * Render a 16-byte AAGUID as a canonical UUID
 * (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) and brand it.
 *
 * @param bytes  Exactly 16 bytes.
 * @returns      Branded {@link AaguidString}.
 * @throws {InternalError}  When input is not 16 bytes.
 */
export function aaguidToUuid(bytes: Uint8Array): AaguidString {
  if (bytes.length !== 16) {
    throw new InternalError(`AAGUID must be 16 bytes, got ${bytes.length}.`);
  }
  const hex = toHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as AaguidString;
}

/**
 * Parse a canonical UUID string back into 16 bytes.
 *
 * @param uuid  `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (case-insensitive).
 * @returns     16-byte AAGUID.
 * @throws {InternalError}  When the input is not a valid UUID format.
 */
export function uuidToAaguid(uuid: string): Uint8Array {
  const cleaned = uuid.replace(/-/g, '');
  if (cleaned.length !== 32) {
    throw new InternalError(`UUID must be 32 hex characters, got ${cleaned.length}.`);
  }
  return fromHex(cleaned);
}

/** The empty AAGUID returned by attestation `'none'`. */
export const ANONYMOUS_AAGUID = '00000000-0000-0000-0000-000000000000' as AaguidString;
