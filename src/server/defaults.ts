import type { CoseAlgName, UserVerificationRequirement } from '../types/webauthn.js';

/** Default per-ceremony timeout (60 s — matches platform-authenticator UX). */
export const DEFAULT_TIMEOUT_MS = 60_000;

/** Default challenge envelope TTL (5 minutes — matches WebAuthn recommendation). */
export const DEFAULT_CHALLENGE_TTL_MS = 5 * 60_000;

/** Minimum TTL accepted on the verifier side. Below this, abuse is more likely than legitimate slowness. */
export const MIN_CHALLENGE_TTL_MS = 30_000;

/** Maximum TTL the verifier accepts (10 minutes). PLAN §9.5. */
export const MAX_CHALLENGE_TTL_MS = 10 * 60_000;

/** Default challenge byte length (32 bytes = 256-bit minimum per spec). */
export const DEFAULT_CHALLENGE_BYTES = 32;

/**
 * Default user-verification requirement.
 *
 * `'required'` is the deliberate fintech-friendly default (NIST AAL3 / PSD2
 * SCA). Consumer-grade flows opt down to `'preferred'` per call. Pinned in
 * PLAN Appendix C.
 */
export const DEFAULT_USER_VERIFICATION: UserVerificationRequirement = 'required';

/**
 * Default `pubKeyCredAlgs` order.
 *
 * EdDSA precedes RS256 because Ed25519 keys are ~32 B vs RSA ≥256 B; RS256 is
 * kept last for Windows Hello compatibility. Pinned in PLAN Appendix C.
 */
export const DEFAULT_PUB_KEY_CRED_ALG_NAMES: ReadonlyArray<CoseAlgName> = ['ES256', 'EdDSA', 'RS256'];
