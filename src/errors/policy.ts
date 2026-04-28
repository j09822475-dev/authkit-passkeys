import { PasskeyError, type PasskeyErrorDetails } from './base.js';
import type { PasskeyErrorCode } from './codes.js';

/**
 * Returned from verification when the authenticator passes the cryptographic
 * checks but violates the configured policy (AAGUID not on allow-list, UV
 * absent when required, transport disallowed).
 *
 * @example
 *   if (!r.ok && r.error instanceof PasskeyPolicyError) {
 *     metrics.incr(`passkey.policy.${r.error.code}`);
 *   }
 */
export class PasskeyPolicyError extends PasskeyError {
  constructor(
    code: PasskeyErrorCode,
    message?: string,
    options?: { cause?: unknown; details?: PasskeyErrorDetails },
  ) {
    super(code, message, options);
    this.name = 'PasskeyPolicyError';
  }
}
