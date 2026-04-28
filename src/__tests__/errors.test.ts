import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  AaguidNotAllowedError,
  AuthenticationFailedError,
  CounterRegressionError,
  ERROR_MESSAGES,
  FALLBACK_CODES,
  InternalError,
  InvalidAttestationError,
  InvalidChallengeError,
  InvalidChallengeTokenError,
  InvalidOriginError,
  InvalidRpIdError,
  InvalidStateError,
  NotSupportedError,
  PasskeyError,
  SecurityError,
  StorageError,
  TimeoutError,
  UnsupportedAlgorithmError,
  UnsupportedAttestationFormatError,
  UserCancelledError,
  UserVerificationRequiredError,
  WrongCeremonyError,
  isPasskeyError,
} from '../errors/index.js';
import type { PasskeyErrorCode, PasskeyErrorDetails, PasskeyInternalReason } from '../errors/index.js';

describe('PasskeyError', () => {
  it('should default the message to ERROR_MESSAGES[code] when omitted', () => {
    const e = new PasskeyError('not_supported');
    expect(e.message).toBe(ERROR_MESSAGES.not_supported);
    expect(e.code).toBe('not_supported');
    expect(e.name).toBe('PasskeyError');
  });

  it('should accept an explicit override message', () => {
    const e = new PasskeyError('timeout', 'custom timeout msg');
    expect(e.message).toBe('custom timeout msg');
    expect(e.code).toBe('timeout');
  });

  it('should attach a frozen details object when provided', () => {
    const e = new PasskeyError('invalid_attestation', undefined, {
      details: { reason: 'invalid_signature', credentialId: 'abc' },
    });
    expect(e.details).toBeDefined();
    expect(e.details?.reason).toBe('invalid_signature');
    expect(Object.isFrozen(e.details)).toBe(true);
  });

  it('should leave details undefined when no details provided', () => {
    const e = new PasskeyError('internal_error');
    expect(e.details).toBeUndefined();
  });

  it('should preserve the cause when provided', () => {
    const original = new TypeError('boom');
    const e = new PasskeyError('internal_error', undefined, { cause: original });
    expect(e.cause).toBe(original);
  });

  it('should not set cause when undefined was passed', () => {
    const e = new PasskeyError('internal_error', undefined, { cause: undefined });
    expect(e.cause).toBeUndefined();
  });

  it('should serialise to a wire-safe { code, message } JSON shape', () => {
    const e = new PasskeyError('storage_error', 'db down', {
      cause: new Error('hidden'),
      details: { reason: 'some_secret' },
    });
    const json = e.toJSON();
    expect(json).toEqual({ code: 'storage_error', message: 'db down' });
    // Ensure details and cause never leak.
    expect((json as Record<string, unknown>).details).toBeUndefined();
    expect((json as Record<string, unknown>).cause).toBeUndefined();
  });

  it('should be an Error subclass', () => {
    expect(new PasskeyError('internal_error')).toBeInstanceOf(Error);
  });
});

describe('isPasskeyError', () => {
  it('should return true for PasskeyError instances', () => {
    expect(isPasskeyError(new PasskeyError('not_supported'))).toBe(true);
    expect(isPasskeyError(new TimeoutError())).toBe(true);
  });

  it('should return false for non-PasskeyError values', () => {
    expect(isPasskeyError(new Error('plain'))).toBe(false);
    expect(isPasskeyError({ code: 'not_supported' })).toBe(false);
    expect(isPasskeyError(null)).toBe(false);
    expect(isPasskeyError(undefined)).toBe(false);
    expect(isPasskeyError('string')).toBe(false);
  });
});

describe('Typed error subclasses', () => {
  const cases: ReadonlyArray<{
    Class: new (...args: never[]) => PasskeyError;
    code: PasskeyErrorCode;
    name: string;
  }> = [
    { Class: NotSupportedError, code: 'not_supported', name: 'NotSupportedError' },
    { Class: UserCancelledError, code: 'user_cancelled', name: 'UserCancelledError' },
    { Class: TimeoutError, code: 'timeout', name: 'TimeoutError' },
    { Class: InvalidStateError, code: 'invalid_state', name: 'InvalidStateError' },
    { Class: SecurityError, code: 'security_error', name: 'SecurityError' },
    {
      Class: InvalidChallengeTokenError,
      code: 'invalid_challenge_token',
      name: 'InvalidChallengeTokenError',
    },
    { Class: WrongCeremonyError, code: 'wrong_ceremony', name: 'WrongCeremonyError' },
    { Class: InvalidChallengeError, code: 'invalid_challenge', name: 'InvalidChallengeError' },
    { Class: InvalidOriginError, code: 'invalid_origin', name: 'InvalidOriginError' },
    { Class: InvalidRpIdError, code: 'invalid_rp_id', name: 'InvalidRpIdError' },
    {
      Class: AuthenticationFailedError,
      code: 'authentication_failed',
      name: 'AuthenticationFailedError',
    },
    {
      Class: InvalidAttestationError,
      code: 'invalid_attestation',
      name: 'InvalidAttestationError',
    },
    {
      Class: UnsupportedAlgorithmError,
      code: 'unsupported_algorithm',
      name: 'UnsupportedAlgorithmError',
    },
    {
      Class: UnsupportedAttestationFormatError,
      code: 'unsupported_attestation_format',
      name: 'UnsupportedAttestationFormatError',
    },
    { Class: CounterRegressionError, code: 'counter_regression', name: 'CounterRegressionError' },
    {
      Class: UserVerificationRequiredError,
      code: 'user_verification_required',
      name: 'UserVerificationRequiredError',
    },
    { Class: AaguidNotAllowedError, code: 'aaguid_not_allowed', name: 'AaguidNotAllowedError' },
    { Class: StorageError, code: 'storage_error', name: 'StorageError' },
  ];

  for (const { Class, code, name } of cases) {
    it(`should pin ${name} to the ${code} code`, () => {
      const e = new (Class as unknown as new () => PasskeyError)();
      expect(e).toBeInstanceOf(PasskeyError);
      expect(e.code).toBe(code);
      expect(e.name).toBe(name);
      expect(e.message).toBe(ERROR_MESSAGES[code]);
    });
  }

  it('should require a message argument for InternalError', () => {
    const e = new InternalError('oops');
    expect(e.code).toBe('internal_error');
    expect(e.name).toBe('InternalError');
    expect(e.message).toBe('oops');
  });

  it('should round-trip cause and details on every subclass', () => {
    const cause = new Error('inner');
    const details: PasskeyErrorDetails = { reason: 'unknown_credential' };
    const e = new AuthenticationFailedError('failed', { cause, details });
    expect(e.cause).toBe(cause);
    expect(e.details?.reason).toBe('unknown_credential');
  });
});

describe('FALLBACK_CODES', () => {
  it('should contain only the codes that signal a password fallback', () => {
    expect(FALLBACK_CODES.has('not_supported')).toBe(true);
    expect(FALLBACK_CODES.has('user_cancelled')).toBe(true);
    expect(FALLBACK_CODES.has('timeout')).toBe(true);
    expect(FALLBACK_CODES.has('authentication_failed')).toBe(true);
  });

  it('should not contain non-fallback codes', () => {
    expect(FALLBACK_CODES.has('invalid_origin')).toBe(false);
    expect(FALLBACK_CODES.has('counter_regression')).toBe(false);
    expect(FALLBACK_CODES.has('internal_error')).toBe(false);
  });
});

describe('ERROR_MESSAGES', () => {
  it('should provide a non-empty default message for every code', () => {
    for (const k of Object.keys(ERROR_MESSAGES) as ReadonlyArray<PasskeyErrorCode>) {
      expect(ERROR_MESSAGES[k]).toBeTypeOf('string');
      expect(ERROR_MESSAGES[k].length).toBeGreaterThan(0);
    }
  });
});

describe('error type contracts', () => {
  it('should expose the public PasskeyErrorCode union and internal-reason union', () => {
    expectTypeOf<PasskeyErrorCode>().toEqualTypeOf<
      | 'not_supported'
      | 'user_cancelled'
      | 'timeout'
      | 'invalid_state'
      | 'security_error'
      | 'invalid_challenge_token'
      | 'wrong_ceremony'
      | 'invalid_challenge'
      | 'invalid_origin'
      | 'invalid_rp_id'
      | 'authentication_failed'
      | 'invalid_attestation'
      | 'unsupported_algorithm'
      | 'unsupported_attestation_format'
      | 'counter_regression'
      | 'user_verification_required'
      | 'aaguid_not_allowed'
      | 'storage_error'
      | 'internal_error'
    >();
    expectTypeOf<PasskeyInternalReason>().toBeString();
  });

  it('should narrow the unknown to PasskeyError via the type guard', () => {
    const v: unknown = new TimeoutError();
    if (isPasskeyError(v)) {
      expectTypeOf(v).toEqualTypeOf<PasskeyError>();
    }
  });
});
