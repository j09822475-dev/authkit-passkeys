import { describe, expect, it } from 'vitest';
import {
  parseAuthenticationOptions,
  parseRegistrationOptions,
} from '../browser/parse-options.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import type { Base64Url } from '../types/webauthn.js';
import type {
  AuthenticationOptionsJSON,
  RegistrationOptionsJSON,
} from '../types/webauthn.js';
import { PasskeyError, isPasskeyError } from '../errors/index.js';

const userIdBytes = new TextEncoder().encode('user-1');
const challengeBytes = new Uint8Array([1, 2, 3, 4]);

const REG_JSON: RegistrationOptionsJSON = {
  rp: { id: 'example.com', name: 'Example' },
  user: {
    id: toBase64Url(userIdBytes),
    name: 'a@b.com',
    displayName: 'A B',
  },
  challenge: toBase64Url(challengeBytes),
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 60_000,
  excludeCredentials: [
    { id: toBase64Url(new Uint8Array([9])), type: 'public-key', transports: ['internal'] },
  ],
  authenticatorSelection: {
    userVerification: 'required',
    residentKey: 'preferred',
  },
  attestation: 'none',
  extensions: { credProps: true },
};

const AUTH_JSON: AuthenticationOptionsJSON = {
  challenge: toBase64Url(challengeBytes),
  timeout: 60_000,
  rpId: 'example.com',
  allowCredentials: [
    { id: toBase64Url(new Uint8Array([42])), type: 'public-key', transports: ['hybrid'] },
  ],
  userVerification: 'required',
  extensions: { credProps: true },
};

describe('parseRegistrationOptions', () => {
  it('should decode every base64url field to ArrayBuffer-compatible bytes', () => {
    const opts = parseRegistrationOptions(REG_JSON);
    expect(opts.user.id).toBeInstanceOf(Uint8Array);
    expect(Array.from(opts.user.id as Uint8Array)).toEqual(Array.from(userIdBytes));
    expect(Array.from(opts.challenge as Uint8Array)).toEqual([1, 2, 3, 4]);
    expect(opts.excludeCredentials).toHaveLength(1);
    expect(opts.excludeCredentials?.[0]?.transports).toEqual(['internal']);
    expect(opts.attestation).toBe('none');
  });

  it('should omit timeout / excludeCredentials / authenticatorSelection / attestation / extensions when not present', () => {
    const minimal: RegistrationOptionsJSON = {
      rp: { id: 'example.com', name: 'Example' },
      user: { id: toBase64Url(userIdBytes), name: 'n', displayName: 'd' },
      challenge: toBase64Url(challengeBytes),
      pubKeyCredParams: [],
    };
    const opts = parseRegistrationOptions(minimal);
    expect(opts.timeout).toBeUndefined();
    expect(opts.excludeCredentials).toBeUndefined();
    expect(opts.authenticatorSelection).toBeUndefined();
    expect(opts.attestation).toBeUndefined();
    expect(opts.extensions).toBeUndefined();
  });

  it('should surface a malformed challenge as the internal_error code (not invalid_attestation)', () => {
    const bad: RegistrationOptionsJSON = {
      ...REG_JSON,
      challenge: '!!!' as Base64Url,
    };
    let caught: unknown;
    try {
      parseRegistrationOptions(bad);
    } catch (e) {
      caught = e;
    }
    expect(isPasskeyError(caught)).toBe(true);
    expect((caught as PasskeyError).code).toBe('internal_error');
  });
});

describe('parseAuthenticationOptions', () => {
  it('should decode every base64url field', () => {
    const opts = parseAuthenticationOptions(AUTH_JSON);
    expect(Array.from(opts.challenge as Uint8Array)).toEqual([1, 2, 3, 4]);
    expect(opts.rpId).toBe('example.com');
    expect(opts.timeout).toBe(60_000);
    expect(opts.allowCredentials?.[0]?.transports).toEqual(['hybrid']);
    expect(opts.userVerification).toBe('required');
  });

  it('should omit allowCredentials / rpId / timeout / extensions when not present', () => {
    const minimal: AuthenticationOptionsJSON = {
      challenge: toBase64Url(challengeBytes),
    };
    const opts = parseAuthenticationOptions(minimal);
    expect(opts.allowCredentials).toBeUndefined();
    expect(opts.rpId).toBeUndefined();
    expect(opts.timeout).toBeUndefined();
    expect(opts.userVerification).toBeUndefined();
    expect(opts.extensions).toBeUndefined();
  });

  it('should surface malformed allowCredentials.id with the internal_error code', () => {
    const bad: AuthenticationOptionsJSON = {
      ...AUTH_JSON,
      allowCredentials: [{ id: '!!!' as Base64Url, type: 'public-key' }],
    };
    let caught: unknown;
    try {
      parseAuthenticationOptions(bad);
    } catch (e) {
      caught = e;
    }
    expect((caught as PasskeyError).code).toBe('internal_error');
  });
});
