import { describe, expect, it } from 'vitest';
import { randomBytes } from '../core/crypto/random.js';
import { InternalError } from '../errors/index.js';

describe('randomBytes', () => {
  it('should return a Uint8Array of the requested length', () => {
    const out = randomBytes(32);
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(32);
  });

  it('should produce different outputs on successive calls', () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    let same = true;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) same = false;
    expect(same).toBe(false);
  });

  it('should accept 1 byte (the lower bound)', () => {
    expect(randomBytes(1).length).toBe(1);
  });

  it('should accept 65536 bytes (the upper bound)', () => {
    expect(randomBytes(65536).length).toBe(65536);
  });

  it('should reject non-integer lengths', () => {
    expect(() => randomBytes(1.5)).toThrow(InternalError);
  });

  it('should reject lengths below 1', () => {
    expect(() => randomBytes(0)).toThrow(InternalError);
    expect(() => randomBytes(-1)).toThrow(InternalError);
  });

  it('should reject lengths above 65536', () => {
    expect(() => randomBytes(65537)).toThrow(InternalError);
  });
});
