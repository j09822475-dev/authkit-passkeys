import { ERROR_MESSAGES, type PasskeyErrorCode } from './codes.js';

/**
 * Server-only structured details attached to a {@link PasskeyError}. Used for
 * audit logs — MUST NOT be forwarded to clients (the `reason` string can
 * distinguish `unknown_credential` from `invalid_signature` and would leak
 * credential-ID enumeration if surfaced; see PLAN §5.6 / §9.10).
 */
export interface PasskeyErrorDetails {
  /** Server-only granular reason. */
  reason?: string;
  aaguid?: string;
  credentialId?: string;
  expectedOrigin?: string | readonly string[];
  actualOrigin?: string;
  expectedRpId?: string;
  expectedChallenge?: string;
  actualChallenge?: string;
  algorithm?: number;
  attestationFormat?: string;
  [key: string]: unknown;
}

/**
 * Base class for every error thrown by `@authkit/passkeys`. Subclasses each
 * pin a single {@link PasskeyErrorCode}; consumers may switch on `.code` or
 * use `instanceof` for the typed subclass.
 *
 * `toJSON()` deliberately omits `cause` and `details` — they may carry stack
 * traces or DB error text and are not safe to forward to a browser. Server
 * logs see the full object; clients see only `{ code, message }`.
 *
 * @example
 *   try { await verifyAuthentication(input); }
 *   catch (e) {
 *     if (isPasskeyError(e) && e.code === 'authentication_failed') {
 *       return new Response('Forbidden', { status: 401 });
 *     }
 *     throw e;
 *   }
 */
export class PasskeyError extends Error {
  /** Stable public error code. */
  readonly code: PasskeyErrorCode;
  /** Server-only structured details. Never serialised by `toJSON()`. */
  readonly details: Readonly<PasskeyErrorDetails> | undefined;

  /**
   * @param code     One of {@link PasskeyErrorCode}.
   * @param message  Optional message override. Defaults to the canonical static message for the code.
   * @param options  Optional `cause` and server-only `details`.
   */
  constructor(
    code: PasskeyErrorCode,
    message?: string,
    options?: { cause?: unknown; details?: PasskeyErrorDetails },
  ) {
    super(
      message ?? ERROR_MESSAGES[code],
      options?.cause === undefined ? undefined : { cause: options.cause },
    );
    this.name = 'PasskeyError';
    this.code = code;
    this.details = options?.details ? Object.freeze({ ...options.details }) : undefined;
  }

  /**
   * Wire-safe JSON shape. Always `{ code, message }` — `cause`, `details`,
   * and stack frames are stripped because they may leak server-internal info
   * or template-interpolated user input. PLAN §5.6 / §9.14.
   *
   * @returns  The wire-safe payload.
   */
  toJSON(): { code: PasskeyErrorCode; message: string } {
    return { code: this.code, message: this.message };
  }
}

/**
 * Type guard — narrows `unknown` to {@link PasskeyError}. Use over
 * `instanceof` when receiving an error across module boundaries (e.g. from
 * a worker, dynamic import, or framework adapter).
 *
 * @param value  The value to test.
 * @returns      `true` iff `value` is a {@link PasskeyError}.
 *
 * @example
 *   if (isPasskeyError(err)) console.log(err.code);
 */
export function isPasskeyError(value: unknown): value is PasskeyError {
  return value instanceof PasskeyError;
}
