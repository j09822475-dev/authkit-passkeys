import { describe, expect, it } from 'vitest';
import { decodeCbor } from '../core/cose/cbor.js';
import { encodeCbor } from './fixtures/cbor-encode.js';
import { PasskeyError } from '../errors/index.js';

describe('decodeCbor', () => {
  it('should decode small unsigned integers', () => {
    const { value, bytesRead } = decodeCbor(encodeCbor(5));
    expect(value).toBe(5);
    expect(bytesRead).toBe(1);
  });

  it('should decode 1-byte unsigned ints', () => {
    expect(decodeCbor(encodeCbor(200)).value).toBe(200);
  });

  it('should decode 2-byte unsigned ints', () => {
    expect(decodeCbor(encodeCbor(0x1234)).value).toBe(0x1234);
  });

  it('should decode 4-byte unsigned ints', () => {
    expect(decodeCbor(encodeCbor(0x12345678)).value).toBe(0x12345678);
  });

  it('should decode negative integers', () => {
    expect(decodeCbor(encodeCbor(-7)).value).toBe(-7);
    expect(decodeCbor(encodeCbor(-1)).value).toBe(-1);
  });

  it('should decode byte strings', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const decoded = decodeCbor(encodeCbor(bytes)).value as Uint8Array;
    expect(Array.from(decoded)).toEqual([1, 2, 3, 4, 5]);
  });

  it('should decode UTF-8 text strings', () => {
    expect(decodeCbor(encodeCbor('hello')).value).toBe('hello');
  });

  it('should decode arrays', () => {
    expect(decodeCbor(encodeCbor([1, 2, 'three'])).value).toEqual([1, 2, 'three']);
  });

  it('should decode maps', () => {
    const m = new Map<unknown, unknown>([
      ['fmt', 'none'],
      [1, 2],
    ]);
    const decoded = decodeCbor(encodeCbor(m as never)).value;
    expect(decoded).toBeInstanceOf(Map);
    expect((decoded as Map<unknown, unknown>).get('fmt')).toBe('none');
    expect((decoded as Map<unknown, unknown>).get(1)).toBe(2);
  });

  it('should decode booleans', () => {
    expect(decodeCbor(encodeCbor(true)).value).toBe(true);
    expect(decodeCbor(encodeCbor(false)).value).toBe(false);
  });

  it('should decode null and undefined', () => {
    expect(decodeCbor(encodeCbor(null)).value).toBeNull();
    expect(decodeCbor(encodeCbor(undefined)).value).toBeUndefined();
  });

  it('should decode tagged values', () => {
    // Tag 0 (date string) wrapping a text string.
    const buf = new Uint8Array([0xc0, 0x63, 0x66, 0x6f, 0x6f]);
    const { value } = decodeCbor(buf);
    expect(value).toEqual({ tag: 0, value: 'foo' });
  });

  it('should decode 16-bit floats (half precision)', () => {
    // Half-precision 1.0 = 0x3c00.
    const buf = new Uint8Array([0xf9, 0x3c, 0x00]);
    expect(decodeCbor(buf).value).toBe(1);
  });

  it('should decode 32-bit floats', () => {
    const buf = new Uint8Array([0xfa, 0x40, 0x49, 0x0f, 0xdb]); // ~PI
    const v = decodeCbor(buf).value as number;
    expect(v).toBeCloseTo(Math.PI, 5);
  });

  it('should decode 64-bit floats', () => {
    const buf = new Uint8Array([0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18]);
    expect(decodeCbor(buf).value).toBe(Math.PI);
  });

  it('should report bytesRead so callers can split off trailing data', () => {
    const enc = encodeCbor('hi');
    const trailing = new Uint8Array(enc.length + 3);
    trailing.set(enc, 0);
    const { bytesRead } = decodeCbor(trailing);
    expect(bytesRead).toBe(enc.length);
  });

  it('should throw a PasskeyError on truncated input', () => {
    let caught: unknown;
    try {
      decodeCbor(new Uint8Array(0));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(PasskeyError);
    expect((caught as PasskeyError).code).toBe('invalid_attestation');
  });

  it('should throw on unsupported simple values (e.g. 0xf8 reserved)', () => {
    expect(() => decodeCbor(new Uint8Array([0xf8, 0x00]))).toThrow(PasskeyError);
  });

  it('should throw on indefinite-length encoding (minor 31)', () => {
    expect(() => decodeCbor(new Uint8Array([0x5f, 0xff]))).toThrow(PasskeyError);
  });

  it('should preserve byte-string slices via copy (not view)', () => {
    const enc = encodeCbor(new Uint8Array([1, 2, 3]));
    const decoded = decodeCbor(enc).value as Uint8Array;
    decoded[0] = 99;
    // Re-decode to confirm the source bytes were not mutated through the slice.
    const second = decodeCbor(enc).value as Uint8Array;
    expect(Array.from(second)).toEqual([1, 2, 3]);
  });
});
