import { AaguidNotAllowedError } from '../../errors/classes.js';
import { ANONYMOUS_AAGUID } from '../../core/encoding/hex.js';
import type { AaguidString } from '../../types/webauthn.js';
import type { AaguidPolicy } from '../../types/options.js';

/**
 * Apply an {@link AaguidPolicy} to a presented `aaguid`. Deny rules win over
 * allow rules. The empty AAGUID is treated specially via `allowAnonymous`.
 *
 * @param policy  Optional policy. When undefined, every AAGUID is accepted.
 * @param aaguid  AAGUID extracted from the attestation.
 * @throws {AaguidNotAllowedError}  When policy rejects the AAGUID.
 *
 * @example
 *   assertAaguidAllowed({ mode: 'allowlist', allow: ENTERPRISE_AAGUIDS }, aaguid);
 */
export function assertAaguidAllowed(
  policy: AaguidPolicy | undefined,
  aaguid: AaguidString,
): void {
  if (!policy) return;

  const isAnonymous = aaguid === ANONYMOUS_AAGUID;

  // Deny-wins precedence (PLAN §2.2 AaguidPolicy).
  if (policy.deny && policy.deny.includes(aaguid)) {
    throw new AaguidNotAllowedError(`AAGUID ${aaguid} is on the deny-list.`, {
      details: { aaguid },
    });
  }

  const mode = policy.mode ?? (policy.allow ? 'allowlist' : policy.deny ? 'denylist' : 'denylist');
  if (mode !== 'allowlist') return;

  if (isAnonymous) {
    if (!policy.allowAnonymous) {
      throw new AaguidNotAllowedError(
        'Anonymous AAGUID is not allowed under allowlist mode (set allowAnonymous: true to permit).',
        { details: { aaguid } },
      );
    }
    return;
  }

  if (!policy.allow || !policy.allow.includes(aaguid)) {
    throw new AaguidNotAllowedError(`AAGUID ${aaguid} is not on the allow-list.`, {
      details: { aaguid },
    });
  }
}
