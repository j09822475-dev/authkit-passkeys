import { UserVerificationRequiredError } from '../../errors/classes.js';
import { AuthenticationFailedError } from '../../errors/classes.js';
import type { AuthenticatorFlags } from '../../types/webauthn.js';

/**
 * Enforce user-presence (UP) and optionally user-verification (UV) policy on
 * a parsed flag byte. UP is mandatory for every passkey ceremony; UV is
 * required iff the caller asked for it.
 *
 * @param flags                Parsed authenticator-data flag bits.
 * @param requireUserVerification  When `true`, `flags.uv` MUST be 1.
 * @throws {AuthenticationFailedError}  When `flags.up` is 0.
 * @throws {UserVerificationRequiredError}  When UV is required but `flags.uv` is 0.
 *
 * @example
 *   assertUserVerification(authData.flags, true);
 */
export function assertUserVerification(
  flags: AuthenticatorFlags,
  requireUserVerification: boolean,
): void {
  if (!flags.up) {
    throw new AuthenticationFailedError('User-presence flag (UP) is required.', {
      details: { reason: 'authenticator_data_parse_failed' },
    });
  }
  if (requireUserVerification && !flags.uv) {
    throw new UserVerificationRequiredError();
  }
}
