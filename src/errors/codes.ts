/**
 * Public error codes emitted by `@authkit/passkeys`.
 *
 * Consumers may switch on these values; adding a new code is a minor version
 * bump, removing or renaming a code is a major version bump.
 *
 * `'authentication-failed'` and `'registration-failed'` are aggregate codes:
 * they intentionally hide enumeration-leaking detail (unknown-credential vs
 * bad-signature, parse-failed vs attestation-invalid). The granular reason is
 * surfaced on `error.details.reason` for SERVER-INTERNAL audit logs only and
 * MUST NOT be forwarded to clients.
 */
export type PasskeyErrorCode =
  | 'not-supported'
  | 'user-cancelled'
  | 'invalid-state'
  | 'security-error'
  | 'timeout'
  | 'no-credentials'
  | 'bad-challenge'
  | 'bad-origin'
  | 'bad-rp-id'
  | 'authentication-failed'
  | 'registration-failed'
  | 'replay-detected'
  | 'aaguid-not-allowed'
  | 'user-verification-required'
  | 'transport-not-allowed'
  | 'unsupported-attestation-format'
  | 'malformed-response'
  | 'unknown';

/**
 * Internal-only reason strings carried on `error.details.reason` for server
 * audit logs. NEVER returned as the top-level `error.code`. These are unstable
 * by design — they may change between minor versions.
 */
export type PasskeyInternalReason =
  | 'unknown-credential'
  | 'bad-signature'
  | 'cose-key-parse-failed'
  | 'attestation-statement-invalid'
  | 'authenticator-data-parse-failed'
  | 'client-data-parse-failed'
  | 'challenge-mismatch'
  | 'challenge-expired'
  | 'challenge-malformed'
  | 'rp-id-hash-mismatch'
  | 'sign-count-regressed'
  | 'backup-eligibility-flipped'
  | 'unsupported-algorithm';

/**
 * Codes that the React/Hono/Next adapter contract treats as "fall back to
 * password / magic-link". Kept as a runtime-readable set so adapters can
 * `if (FALLBACK_REASONS.has(code))` without re-listing the values.
 */
export const FALLBACK_REASONS: ReadonlySet<PasskeyErrorCode> = new Set<PasskeyErrorCode>([
  'not-supported',
  'user-cancelled',
  'no-credentials',
  'authentication-failed',
  'timeout',
]);

/** Default human-readable messages keyed by code. Override per-throw if needed. */
export const ERROR_MESSAGES: Readonly<Record<PasskeyErrorCode, string>> = {
  'not-supported': 'Passkeys are not supported in this environment.',
  'user-cancelled': 'The user cancelled the passkey ceremony.',
  'invalid-state': 'The authenticator is already registered for this user.',
  'security-error': 'The browser refused the ceremony for security reasons.',
  'timeout': 'The passkey ceremony timed out.',
  'no-credentials': 'No matching passkeys were found.',
  'bad-challenge': 'The challenge token is invalid, expired, or already used.',
  'bad-origin': 'The response origin does not match an allowed origin.',
  'bad-rp-id': 'The response RP-ID does not match the configured RP-ID.',
  'authentication-failed': 'Authentication failed.',
  'registration-failed': 'Registration failed.',
  'replay-detected': 'Sign counter regression detected — possible cloned authenticator.',
  'aaguid-not-allowed': 'The authenticator AAGUID is not on the allow-list.',
  'user-verification-required': 'User verification is required but was not performed.',
  'transport-not-allowed': 'The authenticator transport is not allowed.',
  'unsupported-attestation-format': 'The attestation format is not supported.',
  'malformed-response': 'The response payload is malformed or could not be parsed.',
  'unknown': 'An unknown error occurred.',
};
