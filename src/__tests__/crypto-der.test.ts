import { describe, expect, it } from 'vitest';
import { derToRawEcdsa } from '../core/crypto/der.js';
import { PasskeyError } from '../errors/index.js';
import { rawToDerEcdsa } from './fixtures/webauthn.js';

describe('derToRawEcdsa', () => {
  it('should round-trip raw → DER → raw for a P-256 signature', () => {
    const raw = new Uint8Array(64);
    for (let i = 0; i < 64; i++) raw[i] = i + 1;
    const der = rawToDerEcdsa(raw, 32);
    const back = derToRawEcdsa(der, 32);
    expect(Array.from(back)).toEqual(Array.from(raw));
  });

  it('should left-pad short integers to the component length', () => {
    // r = [0x01], s = [0x02] DER encoded.
    const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const out = derToRawEcdsa(der, 32);
    expect(out.length).toBe(64);
    expect(out[31]).toBe(0x01);
    expect(out[63]).toBe(0x02);
    // Everything else should be zero.
    for (let i = 0; i < 31; i++) expect(out[i]).toBe(0);
  });

  it('should throw when the outer SEQUENCE tag is missing', () => {
    expect(() => derToRawEcdsa(new Uint8Array([0x31, 0x00]), 32)).toThrow(PasskeyError);
  });

  it('should throw when the r INTEGER tag is missing', () => {
    expect(() => derToRawEcdsa(new Uint8Array([0x30, 0x02, 0x03, 0x00]), 32)).toThrow(PasskeyError);
  });

  it('should throw when the s INTEGER tag is missing', () => {
    expect(() =>
      derToRawEcdsa(new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x01, 0x03, 0x00]), 32),
    ).toThrow(PasskeyError);
  });

  it('should throw when the SEQUENCE length is invalid', () => {
    // long-form length with n=0 is illegal.
    expect(() => derToRawEcdsa(new Uint8Array([0x30, 0x80]), 32)).toThrow(PasskeyError);
  });

  it('should throw when an integer payload exceeds the component length', () => {
    // r is 33 bytes, but componentLength is 32 with no leading zero to strip.
    const longR = new Uint8Array(33);
    longR.fill(0x11);
    const der = new Uint8Array([
      0x30,
      4 + longR.length + 3,
      0x02,
      longR.length,
      ...longR,
      0x02,
      0x01,
      0x01,
    ]);
    expect(() => derToRawEcdsa(der, 32)).toThrow(PasskeyError);
  });
});
