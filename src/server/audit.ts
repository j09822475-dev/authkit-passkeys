import type { PasskeyErrorCode } from '../errors/codes.js';

/**
 * Audit event emitted by `RelyingParty` at every stage of a ceremony. Subscribe
 * via the `audit` callback in {@link RpConfig}; consumers typically forward to
 * structured logging.
 *
 * NEVER log `error.details.reason` — keep it for server-internal storage only,
 * never returned to the browser.
 */
export type PasskeyAuditEvent =
  | { type: 'registration.start'; userId: string; timestamp: number }
  | { type: 'registration.success'; credentialId: string; aaguid: string; userId: string; timestamp: number }
  | {
      type: 'registration.failure';
      code: PasskeyErrorCode;
      reason?: string;
      userId?: string;
      timestamp: number;
    }
  | { type: 'authentication.start'; userId?: string; timestamp: number }
  | { type: 'authentication.success'; credentialId: string; userId: string; timestamp: number }
  | {
      type: 'authentication.failure';
      code: PasskeyErrorCode;
      reason?: string;
      credentialId?: string;
      userId?: string;
      timestamp: number;
    };

/** User-supplied audit hook — sync or async. Errors thrown are swallowed. */
export type AuditHook = (event: PasskeyAuditEvent) => void | Promise<void>;

/**
 * Safely invoke an optional audit hook. Failures inside the hook MUST NOT
 * crash the ceremony.
 */
export async function emitAudit(hook: AuditHook | undefined, event: PasskeyAuditEvent): Promise<void> {
  if (!hook) return;
  try {
    await hook(event);
  } catch {
    // Swallow — audit must never fail a ceremony.
  }
}
