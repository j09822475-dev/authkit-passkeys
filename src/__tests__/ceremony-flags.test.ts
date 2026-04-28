import { describe, expect, it } from 'vitest';
import { decodeFlags } from '../core/ceremony/flags.js';

describe('decodeFlags', () => {
  it('should decode every individual flag bit', () => {
    expect(decodeFlags(0x01).up).toBe(true);
    expect(decodeFlags(0x04).uv).toBe(true);
    expect(decodeFlags(0x08).be).toBe(true);
    expect(decodeFlags(0x10).bs).toBe(true);
    expect(decodeFlags(0x40).at).toBe(true);
    expect(decodeFlags(0x80).ed).toBe(true);
  });

  it('should return all-false for the zero byte', () => {
    expect(decodeFlags(0)).toEqual({
      up: false,
      uv: false,
      be: false,
      bs: false,
      at: false,
      ed: false,
    });
  });

  it('should decode every flag set together (0xFD; reserved bits 0x02/0x20 ignored)', () => {
    expect(decodeFlags(0xfd)).toEqual({
      up: true,
      uv: true,
      be: true,
      bs: true,
      at: true,
      ed: true,
    });
  });

  it('should ignore reserved bits 0x02 and 0x20', () => {
    expect(decodeFlags(0x02).up).toBe(false);
    expect(decodeFlags(0x22).up).toBe(false);
  });
});
