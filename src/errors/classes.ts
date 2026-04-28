import { PasskeyError, type PasskeyErrorDetails } from './base.js';

/** Thrown when WebAuthn / passkeys are unavailable in the current environment. */
export class NotSupportedError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('not_supported', message, options);
    this.name = 'NotSupportedError';
  }
}

/** Thrown when the user dismisses the browser ceremony prompt. */
export class UserCancelledError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('user_cancelled', message, options);
    this.name = 'UserCancelledError';
  }
}

/** Thrown when the ceremony exceeds the configured timeout. */
export class TimeoutError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('timeout', message, options);
    this.name = 'TimeoutError';
  }
}

/** Thrown when the credential is already registered to this user (duplicate). */
export class InvalidStateError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_state', message, options);
    this.name = 'InvalidStateError';
  }
}

/** Thrown when the browser rejects the ceremony for security reasons (e.g. RP-ID mismatch). */
export class SecurityError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('security_error', message, options);
    this.name = 'SecurityError';
  }
}

/** Thrown when the signed challenge envelope fails HMAC verification, has expired, or is malformed. */
export class InvalidChallengeTokenError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_challenge_token', message, options);
    this.name = 'InvalidChallengeTokenError';
  }
}

/** Thrown when a registration challenge token is replayed at the auth endpoint, or vice-versa. */
export class WrongCeremonyError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('wrong_ceremony', message, options);
    this.name = 'WrongCeremonyError';
  }
}

/** Thrown when `clientData.challenge` does not match the issued challenge. */
export class InvalidChallengeError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_challenge', message, options);
    this.name = 'InvalidChallengeError';
  }
}

/** Thrown when `clientData.origin` is not in the allowed origins list. */
export class InvalidOriginError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_origin', message, options);
    this.name = 'InvalidOriginError';
  }
}

/** Thrown when `authData.rpIdHash` does not match the SHA-256 of the configured RP-ID. */
export class InvalidRpIdError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_rp_id', message, options);
    this.name = 'InvalidRpIdError';
  }
}

/**
 * Thrown for every authentication failure on the public boundary — credential
 * lookup miss and signature mismatch both surface as this single code so
 * timing/error-shape analysis cannot enumerate credential IDs (PLAN §5.6).
 * The granular reason lives on `error.details.reason` for server logs only.
 */
export class AuthenticationFailedError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('authentication_failed', message, options);
    this.name = 'AuthenticationFailedError';
  }
}

/** Thrown when an attestation statement fails format-specific verification. */
export class InvalidAttestationError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('invalid_attestation', message, options);
    this.name = 'InvalidAttestationError';
  }
}

/** Thrown when the credential uses a COSE algorithm with no Web Crypto mapping. */
export class UnsupportedAlgorithmError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('unsupported_algorithm', message, options);
    this.name = 'UnsupportedAlgorithmError';
  }
}

/** Thrown when an attestation `fmt` is not loaded in the current bundle. */
export class UnsupportedAttestationFormatError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('unsupported_attestation_format', message, options);
    this.name = 'UnsupportedAttestationFormatError';
  }
}

/** Thrown when the assertion's sign-counter is strictly less than the stored value. */
export class CounterRegressionError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('counter_regression', message, options);
    this.name = 'CounterRegressionError';
  }
}

/** Thrown when policy requires user verification but `flags.uv` is 0. */
export class UserVerificationRequiredError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('user_verification_required', message, options);
    this.name = 'UserVerificationRequiredError';
  }
}

/** Thrown when the authenticator AAGUID is rejected by the configured AAGUID policy. */
export class AaguidNotAllowedError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('aaguid_not_allowed', message, options);
    this.name = 'AaguidNotAllowedError';
  }
}

/** Thrown when an underlying storage operation fails. Wraps the cause. */
export class StorageError extends PasskeyError {
  constructor(message?: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('storage_error', message, options);
    this.name = 'StorageError';
  }
}

/**
 * Thrown when the library detects a logic bug or programmer error (missing
 * config, invalid types, unreachable code path). If you catch one in
 * production, file a bug.
 */
export class InternalError extends PasskeyError {
  constructor(message: string, options?: { cause?: unknown; details?: PasskeyErrorDetails }) {
    super('internal_error', message, options);
    this.name = 'InternalError';
  }
}
