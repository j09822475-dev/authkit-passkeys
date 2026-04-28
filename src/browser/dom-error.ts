import {
  InvalidStateError,
  NotSupportedError,
  PasskeyError,
  SecurityError,
  TimeoutError,
  UserCancelledError,
} from '../errors/index.js';

/**
 * Map a native `DOMException` from `navigator.credentials.*` to a typed
 * subclass of {@link PasskeyError}.
 *
 * `NotAllowedError` and `AbortError` both surface as
 * {@link UserCancelledError} (browsers conflate the two for ceremony
 * cancellations). `TimeoutError` is preserved as a separate code so the
 * caller can tune retry vs fallback UI.
 *
 * @param error  The caught value from a try/catch.
 * @returns      A typed error preserving the original via `cause`.
 */
export function mapDomException(error: unknown): PasskeyError {
  if (error instanceof PasskeyError) return error;

  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);
  const opts = { cause: error };

  switch (name) {
    case 'NotSupportedError':
      return new NotSupportedError(message, opts);
    case 'NotAllowedError':
    case 'AbortError':
      return new UserCancelledError(message, opts);
    case 'InvalidStateError':
      return new InvalidStateError(message, opts);
    case 'SecurityError':
      return new SecurityError(message, opts);
    case 'TimeoutError':
      return new TimeoutError(message, opts);
    default:
      return new NotSupportedError(message, opts);
  }
}
