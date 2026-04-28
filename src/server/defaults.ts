import { ALL_TRANSPORTS } from '../types/transport.js';
import type { AuthenticatorPolicy } from '../types/policy.js';

/** Default per-ceremony timeout. 60s matches platform-authenticator UX. */
export const DEFAULT_TIMEOUT_MS = 60_000;

/** Default challenge TTL — matches WebAuthn spec recommendation. */
export const DEFAULT_CHALLENGE_TTL_MS = 5 * 60_000;

/** Default challenge byte length (256-bit minimum per spec). */
export const DEFAULT_CHALLENGE_BYTES = 32;

/**
 * Default authenticator policy.
 *
 * `userVerification: 'required'` is the deliberate fintech-friendly default
 * (NIST AAL3 / PSD2 SCA). Consumer-grade flows opt down to `'preferred'`.
 */
export const DEFAULT_POLICY: AuthenticatorPolicy = {
  userVerification: 'required',
  residentKey: 'preferred',
  authenticatorAttachment: undefined,
  aaguidAllowList: undefined,
  aaguidDenyList: undefined,
  transports: ALL_TRANSPORTS,
};

/** Default attestation conveyance — `'none'` is the spec-recommended default. */
export const DEFAULT_ATTESTATION = 'none' as const;
