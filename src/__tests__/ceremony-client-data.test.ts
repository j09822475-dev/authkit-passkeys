import { describe, expect, it } from 'vitest';
import {
  assertExpectedClientData,
  parseClientDataJSON,
} from '../core/ceremony/client-data.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import { utf8 } from './fixtures/webauthn.js';
import {
  InvalidChallengeError,
  InvalidOriginError,
  PasskeyError,
} from '../errors/index.js';

describe('parseClientDataJSON', () => {
  it('should parse a well-formed clientDataJSON buffer', () => {
    const challenge = new Uint8Array([1, 2, 3]);
    const obj = {
      type: 'webauthn.create',
      challenge: toBase64Url(challenge),
      origin: 'https://example.com',
      crossOrigin: false,
    };
    const bytes = utf8(JSON.stringify(obj));
    const cd = parseClientDataJSON(bytes);
    expect(cd.type).toBe('webauthn.create');
    expect(cd.origin).toBe('https://example.com');
    expect(cd.crossOrigin).toBe(false);
    expect(cd.raw).toBe(bytes);
  });

  it('should retain the raw bytes verbatim for downstream hashing', () => {
    const obj = { type: 't', challenge: 'AAAA', origin: 'o' };
    const bytes = utf8(JSON.stringify(obj));
    expect(parseClientDataJSON(bytes).raw).toBe(bytes);
  });

  it('should throw when the bytes are not valid UTF-8', () => {
    expect(() => parseClientDataJSON(new Uint8Array([0xff, 0xfe]))).toThrow(PasskeyError);
  });

  it('should throw when the bytes are not valid JSON', () => {
    expect(() => parseClientDataJSON(utf8('not-json'))).toThrow(PasskeyError);
  });

  it('should throw when type / challenge / origin fields are missing', () => {
    expect(() => parseClientDataJSON(utf8('{}'))).toThrow(PasskeyError);
    expect(() => parseClientDataJSON(utf8('{"type":"x"}'))).toThrow(PasskeyError);
    expect(() => parseClientDataJSON(utf8('{"type":"x","challenge":"y"}'))).toThrow(PasskeyError);
  });
});

describe('assertExpectedClientData', () => {
  const challenge = new Uint8Array([1, 2, 3, 4]);
  const baseObj = {
    type: 'webauthn.create',
    challenge: toBase64Url(challenge),
    origin: 'https://example.com',
    crossOrigin: false,
  };
  const baseBytes = utf8(JSON.stringify(baseObj));

  it('should accept a matching type, challenge, and origin', () => {
    const cd = parseClientDataJSON(baseBytes);
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.create', challenge, 'https://example.com'),
    ).not.toThrow();
  });

  it('should accept the origin when given as an array', () => {
    const cd = parseClientDataJSON(baseBytes);
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.create', challenge, [
        'https://other.com',
        'https://example.com',
      ]),
    ).not.toThrow();
  });

  it('should throw on a type mismatch', () => {
    const cd = parseClientDataJSON(baseBytes);
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.get', challenge, 'https://example.com'),
    ).toThrow(PasskeyError);
  });

  it('should throw InvalidChallengeError on a challenge mismatch', () => {
    const cd = parseClientDataJSON(baseBytes);
    const wrong = new Uint8Array([9, 9, 9, 9]);
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.create', wrong, 'https://example.com'),
    ).toThrow(InvalidChallengeError);
  });

  it('should throw InvalidChallengeError when the challenge in clientData is malformed', () => {
    const obj = {
      type: 'webauthn.create',
      challenge: '!!not-base64!!',
      origin: 'https://example.com',
    };
    const cd = parseClientDataJSON(utf8(JSON.stringify(obj)));
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.create', challenge, 'https://example.com'),
    ).toThrow(InvalidChallengeError);
  });

  it('should throw InvalidOriginError when the origin is not in the allow-list', () => {
    const cd = parseClientDataJSON(baseBytes);
    expect(() =>
      assertExpectedClientData(cd, 'webauthn.create', challenge, 'https://evil.com'),
    ).toThrow(InvalidOriginError);
  });
});
