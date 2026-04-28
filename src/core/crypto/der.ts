import { PasskeyError } from '../../errors/base.js';

/**
 * Convert a DER-SEQUENCE-encoded ECDSA signature
 * (`SEQUENCE { INTEGER r, INTEGER s }`) into the raw `r||s` form Web Crypto
 * expects. Each component is left-padded to `componentLength` bytes (32 for
 * P-256, 48 for P-384, 66 for P-521).
 *
 * Strict — invalid DER throws `'invalid_attestation'` so a malformed
 * signature collapses to the same boundary code as a verifying-but-incorrect
 * signature. This intentionally does not differentiate to a probing client
 * (PLAN §9.3).
 *
 * @param der               DER-encoded signature bytes.
 * @param componentLength   Curve-dependent component length in bytes (32 / 48 / 66).
 * @returns                 Concatenated raw signature (length = 2 × componentLength).
 * @throws {PasskeyError}   Code `'invalid_attestation'` when the DER structure is invalid.
 *
 * @example
 *   const raw = derToRawEcdsa(derSig, 32);
 *   await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, data);
 */
export function derToRawEcdsa(der: Uint8Array, componentLength: number): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) throw bad('expected SEQUENCE');
  const seqLen = readLen(der, i);
  i = seqLen.next;
  if (i + seqLen.length > der.length) throw bad('truncated SEQUENCE');

  if (der[i++] !== 0x02) throw bad('expected INTEGER (r)');
  const rLen = readLen(der, i);
  i = rLen.next;
  const r = der.subarray(i, i + rLen.length);
  i += rLen.length;

  if (der[i++] !== 0x02) throw bad('expected INTEGER (s)');
  const sLen = readLen(der, i);
  i = sLen.next;
  const s = der.subarray(i, i + sLen.length);

  const out = new Uint8Array(componentLength * 2);
  copyComponent(r, out, 0, componentLength);
  copyComponent(s, out, componentLength, componentLength);
  return out;
}

function copyComponent(src: Uint8Array, dst: Uint8Array, offset: number, len: number): void {
  let start = 0;
  while (start < src.length - 1 && src[start] === 0) start++;
  const trimmed = src.subarray(start);
  if (trimmed.length > len) {
    throw bad(`ECDSA component too long: ${trimmed.length} > ${len}`);
  }
  dst.set(trimmed, offset + (len - trimmed.length));
}

function readLen(buf: Uint8Array, i: number): { length: number; next: number } {
  const first = buf[i] as number;
  if (first < 0x80) return { length: first, next: i + 1 };
  const n = first & 0x7f;
  if (n === 0 || n > 4) throw bad(`invalid DER length ${first}`);
  let length = 0;
  for (let k = 0; k < n; k++) length = (length << 8) | (buf[i + 1 + k] as number);
  return { length, next: i + 1 + n };
}

function bad(msg: string): PasskeyError {
  return new PasskeyError('invalid_attestation', `DER: ${msg}`, {
    details: { reason: 'invalid_signature' },
  });
}
