import { describe, expect, it } from 'vitest';
import { assertUserVerification } from '../server/policy/user-verification.js';
import {
  AuthenticationFailedError,
  UserVerificationRequiredError,
} from '../errors/index.js';
import type { AuthenticatorFlags } from '../types/webauthn.js';

const flags = (overrides: Partial<AuthenticatorFlags> = {}): AuthenticatorFlags => ({
  up: true,
  uv: true,
  be: false,
  bs: false,
  at: false,
  ed: false,
  ...overrides,
});

describe('assertUserVerification', () => {
  it('should accept up:true / uv:true with requireUv true', () => {
    expect(() => assertUserVerification(flags(), true)).not.toThrow();
  });

  it('should accept up:true / uv:false when requireUv is false', () => {
    expect(() => assertUserVerification(flags({ uv: false }), false)).not.toThrow();
  });

  it('should throw AuthenticationFailedError when up is false', () => {
    expect(() => assertUserVerification(flags({ up: false }), true)).toThrow(
      AuthenticationFailedError,
    );
  });

  it('should throw UserVerificationRequiredError when requireUv but uv is false', () => {
    expect(() => assertUserVerification(flags({ uv: false }), true)).toThrow(
      UserVerificationRequiredError,
    );
  });
});
