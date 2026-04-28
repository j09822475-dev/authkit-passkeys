import { describe, expect, expectTypeOf, it } from 'vitest';
import { decodeUtf8, encodeUtf8 } from '../core/encoding/utf8.js';

describe('encodeUtf8', () => {
  it('should encode an ASCII string to its byte representation', () => {
    expect(Array.from(encodeUtf8('hi'))).toEqual([0x68, 0x69]);
  });

  it('should encode multi-byte UTF-8 characters correctly', () => {
    expect(Array.from(encodeUtf8('é'))).toEqual([0xc3, 0xa9]);
  });

  it('should accept the empty string', () => {
    expect(encodeUtf8('').length).toBe(0);
  });

  it('should expose a (string) => Uint8Array signature', () => {
    expectTypeOf(encodeUtf8).toEqualTypeOf<(s: string) => Uint8Array>();
  });
});

describe('decodeUtf8', () => {
  it('should decode valid UTF-8 bytes back to a string', () => {
    expect(decodeUtf8(new Uint8Array([0x68, 0x69]))).toBe('hi');
  });

  it('should default to fatal:true and throw on invalid sequences', () => {
    expect(() => decodeUtf8(new Uint8Array([0x80]))).toThrow();
  });

  it('should insert replacement characters when fatal is false', () => {
    expect(decodeUtf8(new Uint8Array([0x80]), false)).toBe('�');
  });

  it('should round-trip multi-byte text through encode/decode', () => {
    const text = 'привіт 🌍';
    expect(decodeUtf8(encodeUtf8(text))).toBe(text);
  });
});
