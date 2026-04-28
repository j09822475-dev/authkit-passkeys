import { PasskeyPolicyError } from '../errors/policy.js';
import { PasskeyVerificationError } from '../errors/verification.js';
import { PasskeyInternalError } from '../errors/internal.js';
import type { ParsedAuthenticatorData } from '../types/ceremony.js';
import type {
  AuthenticatorPolicy,
  AuthenticatorPolicyOverride,
} from '../types/policy.js';
import type { CredentialRecord } from '../types/credential.js';
import type { AuthenticatorTransport } from '../types/transport.js';
import { aaguidToUuid } from '../core/encoding/hex.js';

const POLICY_KEYS: ReadonlySet<string> = new Set([
  'userVerification',
  'residentKey',
  'authenticatorAttachment',
  'aaguidAllowList',
  'aaguidDenyList',
  'transports',
]);

/**
 * Defense-in-depth runtime check: rejects unknown keys on a policy override
 * (catches typos for callers using the JS API without TS strict mode).
 *
 * @param override  Caller-supplied override object (may be undefined).
 * @throws {PasskeyInternalError}  When an unknown key is encountered.
 */
export function assertKnownPolicyKeys(override: AuthenticatorPolicyOverride | undefined): void {
  if (!override) return;
  for (const k of Object.keys(override)) {
    if (!POLICY_KEYS.has(k)) {
      throw new PasskeyInternalError(`Unknown AuthenticatorPolicyOverride key: "${k}".`);
    }
  }
}

/**
 * Merge a base policy with a per-call override. Explicit per-field — never
 * spread `Partial<>` (that would silently widen unknown keys).
 *
 * @param base      The RP-level policy.
 * @param override  Optional per-call delta.
 * @returns         Merged policy.
 */
export function mergePolicy(
  base: AuthenticatorPolicy,
  override: AuthenticatorPolicyOverride | undefined,
): AuthenticatorPolicy {
  assertKnownPolicyKeys(override);
  if (!override) return base;
  return {
    userVerification: override.userVerification ?? base.userVerification,
    residentKey: override.residentKey ?? base.residentKey,
    authenticatorAttachment:
      'authenticatorAttachment' in override ? override.authenticatorAttachment : base.authenticatorAttachment,
    aaguidAllowList: override.aaguidAllowList ?? base.aaguidAllowList,
    aaguidDenyList: override.aaguidDenyList ?? base.aaguidDenyList,
    transports: override.transports ?? base.transports,
  };
}

/**
 * Validate an authenticator-data structure against the configured policy.
 * Used at both registration and authentication time.
 *
 * @param policy  Resolved policy for this ceremony.
 * @param ad      Parsed authenticator data.
 * @param aaguid  UUID-formatted AAGUID (or empty-AAGUID for U2F-style).
 * @throws {PasskeyPolicyError | PasskeyVerificationError}
 */
export function applyPolicy(
  policy: AuthenticatorPolicy,
  ad: ParsedAuthenticatorData,
  aaguid: string,
): void {
  if (!ad.flags.up) {
    throw new PasskeyVerificationError(
      'authentication-failed',
      'User-presence flag (UP) is required.',
      { details: { reason: 'authenticator-data-parse-failed' } },
    );
  }
  if (policy.userVerification === 'required' && !ad.flags.uv) {
    throw new PasskeyPolicyError(
      'user-verification-required',
      'User verification (UV) is required by policy but was not performed.',
    );
  }
  if (policy.aaguidAllowList && policy.aaguidAllowList.length > 0) {
    if (!policy.aaguidAllowList.includes(aaguid)) {
      throw new PasskeyPolicyError('aaguid-not-allowed', `AAGUID ${aaguid} is not on the allow-list.`, {
        details: { aaguid },
      });
    }
  } else if (policy.aaguidDenyList && policy.aaguidDenyList.includes(aaguid)) {
    throw new PasskeyPolicyError('aaguid-not-allowed', `AAGUID ${aaguid} is on the deny-list.`, {
      details: { aaguid },
    });
  }
}

/**
 * Authentication-time replay-detection check. The caller passes the previously
 * stored {@link CredentialRecord} and the counter from the new assertion.
 *
 * Returns the counter the caller should persist plus the resolved
 * `signCountStatic` flag (per §9.3 it can flip on the first authentication).
 *
 * @param record         Stored credential record.
 * @param newSignCount   Counter from the new assertion.
 * @returns              `{ signCount, signCountStatic }` to persist.
 * @throws {PasskeyVerificationError}  Code `'replay-detected'` when the counter regressed on a non-static authenticator.
 */
export function resolveSignCount(
  record: CredentialRecord,
  newSignCount: number,
): { signCount: number; signCountStatic: boolean } {
  if (record.signCountStatic === true) {
    // Known-static authenticator (iCloud/Google PM): counter is meaningless.
    return { signCount: newSignCount, signCountStatic: true };
  }

  if (newSignCount === 0 && record.signCount === 0) {
    // Either a static authenticator we haven't yet identified, or a brand-new credential.
    // First non-zero observation will flip signCountStatic to false.
    return { signCount: 0, signCountStatic: record.signCountStatic ?? false };
  }

  if (newSignCount === 0 && record.signCount > 0) {
    // Unexpected — counter went from non-zero back to zero. Treat as a static
    // authenticator from now on (some sync providers reset across devices).
    return { signCount: 0, signCountStatic: true };
  }

  if (newSignCount <= record.signCount) {
    throw new PasskeyVerificationError(
      'replay-detected',
      `Sign-counter regressed: ${newSignCount} <= ${record.signCount} (possible cloned authenticator).`,
      {
        details: {
          reason: 'sign-count-regressed',
          credentialId: record.credentialId,
        },
      },
    );
  }
  return { signCount: newSignCount, signCountStatic: false };
}

/**
 * Reject if the authenticator-supplied transport is not in the configured
 * allow-list. Authenticators sometimes omit transports — that is allowed.
 *
 * @param policy      Resolved policy.
 * @param transport   Transport from the response (may be undefined).
 * @throws {PasskeyPolicyError}  Code `'transport-not-allowed'` when the transport is disallowed.
 */
export function assertTransportAllowed(
  policy: AuthenticatorPolicy,
  transport: AuthenticatorTransport | undefined,
): void {
  if (!transport) return;
  if (!policy.transports.includes(transport)) {
    throw new PasskeyPolicyError('transport-not-allowed', `Transport "${transport}" is not allowed.`);
  }
}

/** Format a 16-byte AAGUID as a canonical UUID string. */
export function formatAaguid(bytes: Uint8Array): string {
  return aaguidToUuid(bytes);
}
