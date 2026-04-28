/**
 * Shared byte-array helpers. Hoisted so equality / concatenation logic for
 * security-relevant comparisons lives in exactly one place — duplicated
 * implementations are how subtle timing bugs creep in.
 */

/**
 * Concatenate two byte arrays into a fresh `Uint8Array`.
 *
 * @param a  Left operand.
 * @param b  Right operand.
 * @returns  `Uint8Array` of length `a.length + b.length`.
 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Length-checking byte equality. Short-circuits on length mismatch; element
 * comparison short-circuits on first difference. Use for non-secret
 * comparisons (e.g. RP-ID hashes).
 *
 * @param a  Left operand.
 * @param b  Right operand.
 * @returns  `true` iff the contents match.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Constant-time byte equality. Length mismatch short-circuits because the
 * length itself is not a secret; element comparison runs over every byte
 * (XOR-OR fold) so the wall-clock time does not branch on the position of
 * the first differing byte.
 *
 * @param a  Left operand.
 * @param b  Right operand.
 * @returns  `true` iff the contents match.
 */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
