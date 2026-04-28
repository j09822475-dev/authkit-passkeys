import { PasskeyError, type PasskeyErrorDetails } from './base.js';
import type { PasskeyErrorCode } from './codes.js';

/**
 * Thrown by browser-side ceremony helpers (`startRegistration`, `startAuthentication`).
 *
 * Mirrors `navigator.credentials.*` throw-style behavior to keep the surface
 * familiar to developers used to the native API. Common codes: `not-supported`,
 * `user-cancelled`, `invalid-state`, `security-error`, `timeout`.
 *
 * @example
 *   try { await startAuthentication(opts); }
 *   catch (e) {
 *     if (e instanceof PasskeyClientError && e.code === 'user-cancelled') {
 *       showPasswordFallback();
 *     }
 *   }
 */
export class PasskeyClientError extends PasskeyError {
  constructor(
    code: PasskeyErrorCode,
    message?: string,
    options?: { cause?: unknown; details?: PasskeyErrorDetails },
  ) {
    super(code, message, options);
    this.name = 'PasskeyClientError';
  }
}

/**
 * Map a native `DOMException` from `navigator.credentials.*` to a typed
 * {@link PasskeyClientError}.
 *
 * @param error    The caught value from a try/catch around `navigator.credentials.create/get`.
 * @returns        A typed error preserving the original via `cause`.
 *
 * @example
 *   try { await navigator.credentials.create(opts); }
 *   catch (e) { throw mapDomExceptionToClientError(e); }
 */
export function mapDomExceptionToClientError(error: unknown): PasskeyClientError {
  if (error instanceof PasskeyClientError) return error;

  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);

  let code: PasskeyErrorCode;
  switch (name) {
    case 'NotSupportedError':
      code = 'not-supported';
      break;
    case 'NotAllowedError':
    case 'AbortError':
      code = 'user-cancelled';
      break;
    case 'InvalidStateError':
      code = 'invalid-state';
      break;
    case 'SecurityError':
      code = 'security-error';
      break;
    case 'TimeoutError':
      code = 'timeout';
      break;
    default:
      code = 'unknown';
  }

  return new PasskeyClientError(code, message, { cause: error });
}
