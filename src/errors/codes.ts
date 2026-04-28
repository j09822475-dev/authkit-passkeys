/**
 * Public error codes emitted by `@authkit/passkeys`.
 *
 * The string values are part of the v0.1 stability contract — adding a new
 * code is a minor version bump, renaming or removing one is a major version
 * bump (see PLAN Appendix C).
 *
 * `'authentication_failed'` deliberately collapses two internally-distinct
 * failures (credential-lookup miss and signature mismatch) into a single
 * public code so the error path does not become a credential-ID enumeration
 * oracle. The granular reason is logged via the audit hook only and never
 * reaches the browser (see PLAN §5.6 / §9.10 / §9.14).
 */
export type PasskeyErrorCode =
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
  | 'internal_error';

/**
 * Internal-only reason strings carried on `error.details.reason` for
 * server-side audit logs. Never returned as `error.code` and never serialised
 * to the wire by `toJSON()`. These strings are unstable by design — they may
 * change between minor versions.
 */
export type PasskeyInternalReason =
  | 'unknown_credential'
  | 'invalid_signature'
  | 'cose_key_parse_failed'
  | 'attestation_statement_invalid'
  | 'authenticator_data_parse_failed'
  | 'client_data_parse_failed'
  | 'challenge_mismatch'
  | 'challenge_expired'
  | 'challenge_malformed'
  | 'rp_id_hash_mismatch'
  | 'sign_count_regressed'
  | 'backup_eligibility_flipped'
  | 'unsupported_algorithm';

/** Codes that signal "fall back to password / magic-link" to UI adapters. */
export const FALLBACK_CODES: ReadonlySet<PasskeyErrorCode> = new Set<PasskeyErrorCode>([
  'not_supported',
  'user_cancelled',
  'timeout',
  'authentication_failed',
]);

/** Default human-readable messages — kept static (no template-interpolated user input). */
export const ERROR_MESSAGES: Readonly<Record<PasskeyErrorCode, string>> = {
  not_supported: 'Passkeys are not supported in this environment.',
  user_cancelled: 'The user cancelled the passkey ceremony.',
  timeout: 'The passkey ceremony timed out.',
  invalid_state: 'A credential is already registered for this user.',
  security_error: 'The browser refused the ceremony for security reasons.',
  invalid_challenge_token: 'The challenge token is invalid, expired, or already used.',
  wrong_ceremony: 'The challenge token was issued for a different ceremony.',
  invalid_challenge: 'The response challenge does not match the issued challenge.',
  invalid_origin: 'The response origin is not allowed.',
  invalid_rp_id: 'The response RP-ID does not match the configured RP-ID.',
  authentication_failed: 'Authentication failed.',
  invalid_attestation: 'The attestation could not be verified.',
  unsupported_algorithm: 'The credential uses an unsupported algorithm.',
  unsupported_attestation_format: 'The attestation format is not supported.',
  counter_regression: 'Sign-counter regression detected — possible cloned authenticator.',
  user_verification_required: 'User verification is required but was not performed.',
  aaguid_not_allowed: 'The authenticator AAGUID is not on the allow-list.',
  storage_error: 'A storage operation failed.',
  internal_error: 'An internal error occurred.',
};
