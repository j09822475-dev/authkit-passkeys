import type { AuthenticatorFlags } from '../../types/flags.js';

const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;
const ED = 0x80;

/**
 * Decode the authenticator-data flag byte into a typed structure.
 *
 * @param byte  Single flag byte (offset 32 of `authenticatorData`).
 * @returns     {@link AuthenticatorFlags}
 *
 * @example
 *   const flags = decodeFlags(authData[32]);
 *   if (!flags.uv) return err(...);
 */
export function decodeFlags(byte: number): AuthenticatorFlags {
  return {
    up: (byte & UP) !== 0,
    uv: (byte & UV) !== 0,
    be: (byte & BE) !== 0,
    bs: (byte & BS) !== 0,
    at: (byte & AT) !== 0,
    ed: (byte & ED) !== 0,
  };
}
