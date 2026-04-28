import { encodeUtf8 } from '../core/encoding/utf8.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import { signChallengeToken } from './challenge.js';
import { DEFAULT_TIMEOUT_MS, DEFAULT_USER_VERIFICATION } from './defaults.js';
import type { CredentialStore } from '../storage/types.js';
import type {
  AuthenticationOptionsJSON,
  ChallengeToken,
  PublicKeyCredentialDescriptorJSON,
  UserVerificationRequirement,
} from '../types/webauthn.js';
import type { ChallengeSigningKeys } from '../types/options.js';

/** Input shape for {@link generateAuthenticationOptions}. */
export interface GenerateAuthenticationInput<TUserId extends string> {
  rp: { id: string };
  /** Omit for discoverable / passkey-first flows (no `allowCredentials`). */
  user?: { id: TUserId };
  store: CredentialStore<TUserId>;
  /** Required signing keys — see {@link ChallengeSigningKeys}. */
  signingKeys: ChallengeSigningKeys;
  /** Default `'required'`. Same rationale as {@link GenerateRegistrationInput.userVerification}. */
  userVerification?: UserVerificationRequirement;
  /** Default 60_000 ms. */
  timeout?: number;
  /** Optional override for challenge envelope TTL. Default 5 min. */
  challengeTtlMs?: number;
}

/**
 * Build the authentication-options JSON the browser passes to
 * `navigator.credentials.get`, plus a stateless challenge envelope.
 *
 * Pass `user` for non-discoverable flows — the store is consulted to populate
 * `allowCredentials`. Omit `user` for the discoverable / passkey-first flow:
 * `allowCredentials` is left empty (no privacy-leaking enumeration of
 * credentials), and the user is identified after the ceremony from the
 * stored {@link CredentialRecord} (PLAN §9.10).
 *
 * @param input  Required configuration — see {@link GenerateAuthenticationInput}.
 * @returns      `{ options, challengeToken }`.
 *
 * @example
 *   // Discoverable / passkey-first login:
 *   const { options, challengeToken } = await generateAuthenticationOptions({
 *     rp: { id: 'example.com' },
 *     store,
 *     signingKeys: PASSKEY_SIGNING_KEYS,
 *   });
 */
export async function generateAuthenticationOptions<TUserId extends string>(
  input: GenerateAuthenticationInput<TUserId>,
): Promise<{ options: AuthenticationOptionsJSON; challengeToken: ChallengeToken }> {
  let allowCredentials: PublicKeyCredentialDescriptorJSON[] | undefined;
  if (input.user) {
    const stored = await input.store.listByUserId(input.user.id);
    allowCredentials = stored.map((c) => ({
      id: c.credentialId,
      type: 'public-key' as const,
      ...(c.transports.length ? { transports: c.transports } : {}),
    }));
  }

  const userIdBytes = input.user ? encodeUtf8(input.user.id) : undefined;
  const { challenge, challengeToken } = await signChallengeToken({
    signingKeys: input.signingKeys,
    ceremony: 'auth',
    ...(userIdBytes ? { userId: userIdBytes } : {}),
    ...(input.challengeTtlMs !== undefined ? { ttlMs: input.challengeTtlMs } : {}),
  });

  const options: AuthenticationOptionsJSON = {
    challenge: toBase64Url(challenge),
    timeout: input.timeout ?? DEFAULT_TIMEOUT_MS,
    rpId: input.rp.id,
    ...(allowCredentials ? { allowCredentials } : {}),
    userVerification: input.userVerification ?? DEFAULT_USER_VERIFICATION,
  };

  return { options, challengeToken };
}
