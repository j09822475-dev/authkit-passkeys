import { describe, expect, it } from 'vitest';
import { concatBytes, equalBytes, timingSafeEqualBytes } from '../core/crypto/bytes.js';

describe('concatBytes', () => {
  it('should concatenate two byte arrays into a fresh Uint8Array', () => {
    const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3, 4]));
    expect(Array.from(out)).toEqual([1, 2, 3, 4]);
  });

  it('should accept empty operands', () => {
    expect(Array.from(concatBytes(new Uint8Array(0), new Uint8Array([5])))).toEqual([5]);
    expect(Array.from(concatBytes(new Uint8Array([5]), new Uint8Array(0)))).toEqual([5]);
  });

  it('should not alias either input', () => {
    const a = new Uint8Array([1]);
    const b = new Uint8Array([2]);
    const out = concatBytes(a, b);
    out[0] = 99;
    expect(a[0]).toBe(1);
    expect(b[0]).toBe(2);
  });
});

describe('equalBytes', () => {
  it('should return true on byte-for-byte equal arrays', () => {
    expect(equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it('should return false on length mismatch', () => {
    expect(equalBytes(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('should return false on a content mismatch', () => {
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 9]))).toBe(false);
  });

  it('should treat two empty arrays as equal', () => {
    expect(equalBytes(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('timingSafeEqualBytes', () => {
  it('should return true on equal byte arrays', () => {
    expect(timingSafeEqualBytes(new Uint8Array([5, 6]), new Uint8Array([5, 6]))).toBe(true);
  });

  it('should return false on unequal arrays of the same length', () => {
    expect(timingSafeEqualBytes(new Uint8Array([5, 6]), new Uint8Array([5, 7]))).toBe(false);
  });

  it('should short-circuit only on length mismatch', () => {
    expect(timingSafeEqualBytes(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it('should return true for two zero-length arrays', () => {
    expect(timingSafeEqualBytes(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});
