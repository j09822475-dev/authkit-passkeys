import {
  InternalError,
  InvalidStateError,
  NotSupportedError,
  PasskeyError,
  SecurityError,
  TimeoutError,
  UserCancelledError,
} from '../errors/index.js';

/**
 * Threshold (ms) above which a `NotAllowedError` is treated as a timeout
 * rather than a user cancellation. Browsers reuse `NotAllowedError` for both
 * outcomes; the elapsed time is the only signal available to disambiguate
 * them. Tuned to match WebAuthn's typical 60 s default — anything that takes
 * longer than half that is almost certainly the UA-side timeout firing
 * (PLAN §5.4 / §9.8).
 */
const NOT_ALLOWED_TIMEOUT_THRESHOLD_MS = 30_000;

/**
 * Map a native `DOMException` from `navigator.credentials.*` to a typed
 * subclass of {@link PasskeyError}.
 *
 * `NotAllowedError` is disambiguated by elapsed time: short ceremonies
 * surface as {@link UserCancelledError}; long ones surface as
 * {@link TimeoutError} so the documented `FALLBACK_CODES` branching gets the
 * right code (PLAN §5.4). `AbortError` is always treated as a user
 * cancellation. Unknown DOMExceptions surface as {@link InternalError} so
 * unrelated bugs do not silently route to the password fallback.
 *
 * @param error      The caught value from a try/catch.
 * @param elapsedMs  Optional milliseconds since the ceremony began — used to
 *                   disambiguate `NotAllowedError`.
 * @returns          A typed error preserving the original via `cause`.
 */
export function mapDomException(error: unknown, elapsedMs?: number): PasskeyError {
  if (error instanceof PasskeyError) return error;

  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);
  const opts = { cause: error };

  switch (name) {
    case 'NotSupportedError':
      return new NotSupportedError(message, opts);
    case 'NotAllowedError':
      if (elapsedMs !== undefined && elapsedMs >= NOT_ALLOWED_TIMEOUT_THRESHOLD_MS) {
        return new TimeoutError(message, opts);
      }
      return new UserCancelledError(message, opts);
    case 'AbortError':
      return new UserCancelledError(message, opts);
    case 'InvalidStateError':
      return new InvalidStateError(message, opts);
    case 'SecurityError':
      return new SecurityError(message, opts);
    case 'TimeoutError':
      return new TimeoutError(message, opts);
    default:
      return new InternalError(message, opts);
  }
}
