/**
 * UTF-8 encode a string to bytes via `TextEncoder` (no Node `Buffer` dependency).
 *
 * @param str  Input string.
 * @returns    UTF-8 encoded bytes.
 * @example    encodeUtf8("hello") // Uint8Array([104, 101, ...])
 */
export function encodeUtf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * UTF-8 decode bytes to a string. Strict by default — invalid sequences throw.
 *
 * @param bytes   Input bytes.
 * @param fatal   When `true` (default), invalid UTF-8 throws. When `false`,
 *                replacement characters are inserted.
 * @returns       Decoded string.
 * @throws        `TypeError` when `fatal` is `true` and `bytes` is not valid UTF-8.
 */
export function decodeUtf8(bytes: Uint8Array, fatal: boolean = true): string {
  return new TextDecoder('utf-8', { fatal }).decode(bytes);
}
