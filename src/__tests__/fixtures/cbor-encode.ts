/**
 * Tiny CBOR encoder used by tests to build deterministic WebAuthn fixtures
 * (COSE keys and attestation objects). NOT shipped in the library bundle.
 */

export type CborInput =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborInput[]
  | Map<CborInput, CborInput>;

function encodeHead(major: number, value: number): Uint8Array {
  if (value < 24) return new Uint8Array([(major << 5) | value]);
  if (value < 0x100) return new Uint8Array([(major << 5) | 24, value]);
  if (value < 0x10000) {
    const out = new Uint8Array(3);
    out[0] = (major << 5) | 25;
    out[1] = (value >> 8) & 0xff;
    out[2] = value & 0xff;
    return out;
  }
  if (value < 0x1_0000_0000) {
    const out = new Uint8Array(5);
    out[0] = (major << 5) | 26;
    out[1] = (value >>> 24) & 0xff;
    out[2] = (value >>> 16) & 0xff;
    out[3] = (value >>> 8) & 0xff;
    out[4] = value & 0xff;
    return out;
  }
  throw new Error('CBOR encoder: value too large for test encoder.');
}

function concat(arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function encodeCbor(value: CborInput): Uint8Array {
  if (typeof value === 'number' && Number.isInteger(value)) {
    if (value >= 0) return encodeHead(0, value);
    return encodeHead(1, -1 - value);
  }
  if (typeof value === 'bigint') {
    if (value >= 0n) return encodeHead(0, Number(value));
    return encodeHead(1, Number(-1n - value));
  }
  if (value instanceof Uint8Array) {
    return concat([encodeHead(2, value.length), value]);
  }
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat([encodeHead(3, bytes.length), bytes]);
  }
  if (Array.isArray(value)) {
    return concat([encodeHead(4, value.length), ...value.map((v) => encodeCbor(v))]);
  }
  if (value instanceof Map) {
    const parts: Uint8Array[] = [encodeHead(5, value.size)];
    for (const [k, v] of value.entries()) {
      parts.push(encodeCbor(k));
      parts.push(encodeCbor(v));
    }
    return concat(parts);
  }
  if (value === false) return new Uint8Array([0xf4]);
  if (value === true) return new Uint8Array([0xf5]);
  if (value === null) return new Uint8Array([0xf6]);
  if (value === undefined) return new Uint8Array([0xf7]);
  throw new Error(`CBOR encoder: unsupported value ${typeof value}`);
}
