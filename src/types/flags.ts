/**
 * Decoded authenticator-data flag byte.
 *
 * @see https://www.w3.org/TR/webauthn-3/#authenticator-data
 */
export interface AuthenticatorFlags {
  /** UP — User Present (touch / button / proximity). */
  readonly up: boolean;
  /** UV — User Verified (PIN / biometric). */
  readonly uv: boolean;
  /** BE — Backup Eligible. Becomes 1 and never reverts. */
  readonly be: boolean;
  /** BS — Backup State (currently backed up). May flip both ways. */
  readonly bs: boolean;
  /** AT — Attested credential data is present. */
  readonly at: boolean;
  /** ED — Extension data is present. */
  readonly ed: boolean;
}
