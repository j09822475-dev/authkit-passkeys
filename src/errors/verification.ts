import { PasskeyError, type PasskeyErrorDetails } from './base.js';
import type { PasskeyErrorCode } from './codes.js';

/**
 * Returned (NOT thrown) from `RelyingParty.finishRegistration` / `.finishAuthentication`
 * when verification fails (bad challenge, bad origin, signature mismatch, replay).
 *
 * @example
 *   const r = await rp.finishAuthentication(input);
 *   if (!r.ok && r.error instanceof PasskeyVerificationError) {
 *     auditLog.warn(r.error.code, r.error.details);
 *   }
 */
export class PasskeyVerificationError extends PasskeyError {
  constructor(
    code: PasskeyErrorCode,
    message?: string,
    options?: { cause?: unknown; details?: PasskeyErrorDetails },
  ) {
    super(code, message, options);
    this.name = 'PasskeyVerificationError';
  }
}
