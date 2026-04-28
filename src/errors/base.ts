import { ERROR_MESSAGES, type PasskeyErrorCode } from './codes.js';

/**
 * Structured details attached to a {@link PasskeyError}. Used for server-side
 * audit logs only — MUST NOT be forwarded to clients (may carry the internal
 * `reason` string that distinguishes `unknown-credential` from `bad-signature`).
 */
export interface PasskeyErrorDetails {
  /** Server-only granular reason — see {@link PasskeyInternalReason}. */
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
 * Base class for every error thrown or returned by `@authkit/passkeys`.
 *
 * @example
 *   if (err instanceof PasskeyError && err.code === 'user-cancelled') {
 *     showFallback();
 *   }
 */
export class PasskeyError extends Error {
  /** Stable public error code — see {@link PasskeyErrorCode}. */
  readonly code: PasskeyErrorCode;
  /** Server-only structured details. Never forward to clients. */
  readonly details: Readonly<PasskeyErrorDetails> | undefined;

  /**
   * @param code     One of {@link PasskeyErrorCode}
   * @param message  Optional human-readable message (defaults to the canonical message for the code)
   * @param options  Optional `cause` (Error) and `details` (server-only structured info)
   */
  constructor(
    code: PasskeyErrorCode,
    message?: string,
    options?: { cause?: unknown; details?: PasskeyErrorDetails },
  ) {
    super(message ?? ERROR_MESSAGES[code], options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'PasskeyError';
    this.code = code;
    this.details = options?.details ? Object.freeze({ ...options.details }) : undefined;
  }
}
