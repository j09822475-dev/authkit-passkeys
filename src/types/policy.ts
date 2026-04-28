import type { AuthenticatorTransport } from './transport.js';
import type {
  AuthenticatorAttachment,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from './webauthn-json.js';

/**
 * Authenticator-acceptance policy applied at registration AND authentication.
 *
 * The default policy ships with `userVerification: 'required'` (NIST AAL3 /
 * PSD2 SCA-friendly). Consumer-grade flows opt down to `'preferred'` per call.
 */
export interface AuthenticatorPolicy {
  userVerification: UserVerificationRequirement;
  residentKey: ResidentKeyRequirement;
  authenticatorAttachment: AuthenticatorAttachment | undefined;
  /** If set, ONLY these AAGUIDs are accepted (overrides denyList). */
  aaguidAllowList: readonly string[] | undefined;
  /** If set, these AAGUIDs are rejected. Ignored when allowList is non-empty. */
  aaguidDenyList: readonly string[] | undefined;
  /** Transports that are accepted. Authenticators reporting an unlisted transport are rejected. */
  transports: readonly AuthenticatorTransport[];
}

/**
 * Per-call policy override. Hand-written (rather than `Partial<AuthenticatorPolicy>`)
 * so that under `exactOptionalPropertyTypes`, typos are rejected at compile
 * time instead of being silently widened by structural rules. Plain-JS callers
 * are still protected by a runtime `assertKnownPolicyKeys` check.
 */
export interface AuthenticatorPolicyOverride {
  userVerification?: UserVerificationRequirement;
  residentKey?: ResidentKeyRequirement;
  authenticatorAttachment?: AuthenticatorAttachment;
  aaguidAllowList?: readonly string[];
  aaguidDenyList?: readonly string[];
  transports?: readonly AuthenticatorTransport[];
}

/**
 * Per-tenant / per-request RelyingParty config delta. Returned by the
 * `resolveConfig` callback to override the constructor defaults for a single
 * ceremony (multi-tenant SaaS, per-environment overrides, etc.).
 */
export interface RpConfigOverride {
  rpName?: string;
  rpId?: string;
  origin?: string | readonly string[];
  defaultTimeoutMs?: number;
  policy?: AuthenticatorPolicyOverride;
}
