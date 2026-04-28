import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  assertBase64Url,
  base64UrlToUtf8,
  fromBase64Url,
  toBase64Url,
  utf8ToBase64Url,
} from '../core/encoding/base64url.js';
import { PasskeyError, isPasskeyError } from '../errors/index.js';
import type { Base64Url } from '../types/webauthn.js';

describe('toBase64Url', () => {
  it('should encode bytes using the URL-safe alphabet without padding', () => {
    expect(toBase64Url(new Uint8Array([0xfb, 0xff]))).toBe('-_8');
  });

  it('should return a deterministic empty string for an empty input', () => {
    expect(toBase64Url(new Uint8Array(0))).toBe('');
  });

  it('should round-trip through fromBase64Url byte-for-byte', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 250, 255]);
    const encoded = toBase64Url(bytes);
    expect(fromBase64Url(encoded)).toEqual(bytes);
  });

  it('should produce a Base64Url-branded string', () => {
    expectTypeOf(toBase64Url(new Uint8Array(0))).toEqualTypeOf<Base64Url>();
  });
});

describe('fromBase64Url', () => {
  it('should decode an unpadded base64url string', () => {
    expect(Array.from(fromBase64Url('AQID'))).toEqual([1, 2, 3]);
  });

  it('should accept input with explicit = padding', () => {
    expect(Array.from(fromBase64Url('AQID===='))).toEqual([1, 2, 3]);
  });

  it('should accept the standard base64 alphabet (+/) in addition to -_', () => {
    expect(Array.from(fromBase64Url('+/8='))).toEqual([0xfb, 0xff]);
  });

  it('should throw a PasskeyError with the default invalid_attestation code on illegal characters', () => {
    let caught: unknown;
    try {
      fromBase64Url('not*valid');
    } catch (e) {
      caught = e;
    }
    expect(isPasskeyError(caught)).toBe(true);
    expect((caught as PasskeyError).code).toBe('invalid_attestation');
    expect((caught as PasskeyError).details?.reason).toBe('challenge_malformed');
  });

  it('should respect the errorCode override when provided', () => {
    let caught: unknown;
    try {
      fromBase64Url('!!', 'internal_error');
    } catch (e) {
      caught = e;
    }
    expect(isPasskeyError(caught)).toBe(true);
    expect((caught as PasskeyError).code).toBe('internal_error');
  });
});

describe('assertBase64Url', () => {
  it('should accept a valid string and strip the trailing padding', () => {
    expect(assertBase64Url('AQID==')).toBe('AQID');
  });

  it('should accept the empty string as a degenerate valid value', () => {
    expect(assertBase64Url('')).toBe('');
  });

  it('should reject illegal characters with the default invalid_attestation code', () => {
    let caught: unknown;
    try {
      assertBase64Url('***');
    } catch (e) {
      caught = e;
    }
    expect(isPasskeyError(caught)).toBe(true);
    expect((caught as PasskeyError).code).toBe('invalid_attestation');
  });

  it('should accept the errorCode override on rejection', () => {
    let caught: unknown;
    try {
      assertBase64Url('@@', 'internal_error');
    } catch (e) {
      caught = e;
    }
    expect((caught as PasskeyError).code).toBe('internal_error');
  });

  it('should brand its return as Base64Url', () => {
    expectTypeOf(assertBase64Url('AQID')).toEqualTypeOf<Base64Url>();
  });
});

describe('utf8ToBase64Url / base64UrlToUtf8', () => {
  it('should round-trip ASCII text', () => {
    const encoded = utf8ToBase64Url('hello');
    expect(base64UrlToUtf8(encoded)).toBe('hello');
  });

  it('should round-trip multi-byte UTF-8 text', () => {
    const encoded = utf8ToBase64Url('héllo 🌍');
    expect(base64UrlToUtf8(encoded)).toBe('héllo 🌍');
  });

  it('should throw when decoding bytes that are not valid UTF-8', () => {
    // 0x80 alone is an illegal UTF-8 continuation byte.
    const invalid = toBase64Url(new Uint8Array([0x80]));
    expect(() => base64UrlToUtf8(invalid)).toThrow();
  });
});
