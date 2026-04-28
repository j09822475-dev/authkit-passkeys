import { PasskeyInternalError } from '../errors/internal.js';

/**
 * Throws a {@link PasskeyInternalError} when `condition` is falsy. Used to
 * mark logic invariants the type system can't prove (post-narrowing checks,
 * non-null assertions on map lookups, etc.). NEVER call this for user input —
 * use a `Result` for those.
 *
 * @param condition  Predicate; must be truthy.
 * @param message    Description of the violated invariant.
 * @throws {PasskeyInternalError}  When `condition` is falsy.
 *
 * @example
 *   const key = registry.get(fmt);
 *   invariant(key, `attestation registry missing ${fmt}`);
 *   // key is now narrowed to non-undefined
 */
export function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new PasskeyInternalError(`Invariant violated: ${message}`);
  }
}
