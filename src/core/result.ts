/**
 * Tagged-union result type used everywhere we'd rather return a typed error
 * than throw. Discriminate on `result.ok`.
 *
 * @example
 *   const r = await rp.finishAuthentication(input);
 *   if (!r.ok) return reject(r.error.code);
 *   await session.create(r.value.userId);
 */
export type Result<T, E = Error> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };

/**
 * Construct a success result.
 *
 * @param value  Success payload.
 * @returns      `{ ok: true, value }`
 * @example      return ok(record);
 */
export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

/**
 * Construct an error result.
 *
 * @param error  Error payload.
 * @returns      `{ ok: false, error }`
 * @example      return err(new PasskeyVerificationError('bad-challenge'));
 */
export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}
