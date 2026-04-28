import { encodeUtf8 } from '../core/encoding/utf8.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import { coseAlgId } from '../core/cose/algorithms.js';
import { issueChallenge } from './challenge.js';
import {
  DEFAULT_PUB_KEY_CRED_ALG_NAMES,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_USER_VERIFICATION,
} from './defaults.js';
import type { CredentialStore } from '../storage/types.js';
import type {
  AttestationConveyancePreference,
  AuthenticatorAttachment,
  Base64Url,
  ChallengeToken,
  CoseAlgName,
  PublicKeyCredentialDescriptorJSON,
  RegistrationOptionsJSON,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from '../types/webauthn.js';
import type { ChallengeSigningKeys } from '../types/options.js';

/** Input shape for {@link generateRegistrationOptions}. */
export interface GenerateRegistrationInput<TUserId extends string> {
  rp: { id: string; name: string };
  user: { id: TUserId; name: string; displayName: string };
  store: CredentialStore<TUserId>;
  /**
   * Required. Caller-supplied signing keys for the stateless challenge
   * envelope. No global / env-var lookup — workerd, edge-light, deno bind
   * secrets per-request. See {@link ChallengeSigningKeys}.
   */
  signingKeys: ChallengeSigningKeys;
  /**
   * Default `['ES256','EdDSA','RS256']`. Order = preference. EdDSA precedes
   * RS256 because Ed25519 keys are ~32 B vs RSA ≥256 B. Pinned in PLAN
   * Appendix C.
   */
  pubKeyCredAlgs?: ReadonlyArray<CoseAlgName>;
  /**
   * Default `'required'`. The library targets fintech/healthcare audiences
   * where NIST AAL3 / PSD2 SCA require user verification on every ceremony.
   * Consumer-grade flows can opt down to `'preferred'` explicitly. Pinned in
   * PLAN Appendix C.
   */
  userVerification?: UserVerificationRequirement;
  /** Default `'preferred'`. */
  residentKey?: ResidentKeyRequirement;
  /** Default unset (lets the platform pick). */
  authenticatorAttachment?: AuthenticatorAttachment;
  /** Default 60_000 ms. */
  timeout?: number;
  /** Default `'none'`. */
  attestation?: AttestationConveyancePreference;
  /** Optional override for challenge envelope TTL. Default 5 min. */
  challengeTtlMs?: number;
}

/**
 * Build the registration-options JSON the browser passes to
 * `navigator.credentials.create`, plus a stateless challenge envelope.
 *
 * The store is used only to populate `excludeCredentials` (so the user is
 * not prompted to register a credential they already have on this device).
 * No mutation — the call site owns the transaction boundary on
 * `verifyRegistration` → `store.create`.
 *
 * @param input  Required configuration — see {@link GenerateRegistrationInput}.
 * @returns      `{ options, challengeToken }`.
 *
 * @example
 *   const { options, challengeToken } = await generateRegistrationOptions({
 *     rp: { id: 'example.com', name: 'Example' },
 *     user: { id: user.id, name: user.email, displayName: user.name },
 *     store,
 *     signingKeys: PASSKEY_SIGNING_KEYS,
 *   });
 *   setCookie('passkey_reg', challengeToken, { httpOnly: true, sameSite: 'strict', maxAge: 300 });
 *   return Response.json(options);
 */
export async function generateRegistrationOptions<TUserId extends string>(
  input: GenerateRegistrationInput<TUserId>,
): Promise<{ options: RegistrationOptionsJSON; challengeToken: ChallengeToken }> {
  const algNames = input.pubKeyCredAlgs ?? DEFAULT_PUB_KEY_CRED_ALG_NAMES;
  const pubKeyCredParams = algNames.map((name) => ({
    type: 'public-key' as const,
    alg: coseAlgId(name),
  }));

  const userIdBytes = encodeUtf8(input.user.id);
  const existing = await input.store.listByUserId(input.user.id);
  const excludeCredentials: PublicKeyCredentialDescriptorJSON[] = existing.map((c) => ({
    id: c.credentialId,
    type: 'public-key' as const,
    ...(c.transports.length ? { transports: c.transports } : {}),
  }));

  const userVerification = input.userVerification ?? DEFAULT_USER_VERIFICATION;
  const residentKey = input.residentKey ?? 'preferred';

  const { challenge, challengeToken } = await issueChallenge({
    signingKeys: input.signingKeys,
    ceremony: 'reg',
    userId: userIdBytes,
    ...(input.challengeTtlMs !== undefined ? { ttlMs: input.challengeTtlMs } : {}),
  });

  const options: RegistrationOptionsJSON = {
    rp: { id: input.rp.id, name: input.rp.name },
    user: {
      id: toBase64Url(userIdBytes),
      name: input.user.name,
      displayName: input.user.displayName,
    },
    challenge: toBase64Url(challenge) as Base64Url,
    pubKeyCredParams,
    timeout: input.timeout ?? DEFAULT_TIMEOUT_MS,
    excludeCredentials,
    authenticatorSelection: {
      residentKey,
      requireResidentKey: residentKey === 'required',
      userVerification,
      ...(input.authenticatorAttachment
        ? { authenticatorAttachment: input.authenticatorAttachment }
        : {}),
    },
    attestation: input.attestation ?? 'none',
  };

  return { options, challengeToken };
}
