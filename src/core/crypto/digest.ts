import { subtle } from '#webcrypto-shim';

/**
 * SHA-256 digest via WebCrypto.
 *
 * @param data  Bytes to hash.
 * @returns     32-byte SHA-256 digest.
 *
 * @example
 *   const rpIdHash = await sha256(new TextEncoder().encode('acme.com'));
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}
