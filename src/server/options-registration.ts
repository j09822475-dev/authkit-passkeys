import { toBase64Url } from '../core/encoding/base64url.js';
import { randomBytes } from '../core/crypto/random.js';
import { DEFAULT_PUB_KEY_CRED_PARAMS } from '../core/cose/algorithms.js';
import type {
  AttestationConveyancePreference,
  AuthenticatorAttachment,
  AuthenticatorSelectionCriteria,
  PasskeyExtensionsInput,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from '../types/webauthn-json.js';
import type { AuthenticatorPolicy } from '../types/policy.js';
import { DEFAULT_ATTESTATION, DEFAULT_CHALLENGE_BYTES, DEFAULT_TIMEOUT_MS } from './defaults.js';

export interface BuildRegistrationOptionsInput {
  rpName: string;
  rpId: string | undefined;
  policy: AuthenticatorPolicy;
  user: { id: Uint8Array; name: string; displayName: string };
  excludeCredentials: ReadonlyArray<{ id: string; transports?: readonly string[] }>;
  attestation: AttestationConveyancePreference;
  extensions: PasskeyExtensionsInput | undefined;
  timeoutMs: number;
}

export interface BuildRegistrationOptionsResult {
  options: PublicKeyCredentialCreationOptionsJSON;
  challenge: Uint8Array;
}

/**
 * Internal helper. Build the `PublicKeyCredentialCreationOptionsJSON` payload
 * the browser will pass to `navigator.credentials.create`. The challenge bytes
 * are returned alongside so the caller can persist them via {@link ChallengeStore}.
 *
 * This is NOT re-exported from `server/index.ts`; consumers go through
 * `RelyingParty.startRegistration`.
 */
export function _buildRegistrationOptions(
  input: BuildRegistrationOptionsInput,
): BuildRegistrationOptionsResult {
  const challenge = randomBytes(DEFAULT_CHALLENGE_BYTES);

  const authenticatorSelection: AuthenticatorSelectionCriteria = {
    residentKey: input.policy.residentKey,
    requireResidentKey: input.policy.residentKey === 'required',
    userVerification: input.policy.userVerification satisfies UserVerificationRequirement,
  };
  if (input.policy.authenticatorAttachment) {
    authenticatorSelection.authenticatorAttachment =
      input.policy.authenticatorAttachment satisfies AuthenticatorAttachment;
  }

  void (input.policy.residentKey satisfies ResidentKeyRequirement);

  const exclude: PublicKeyCredentialDescriptorJSON[] = input.excludeCredentials.map((c) => ({
    id: c.id,
    type: 'public-key',
    ...(c.transports ? { transports: c.transports as PublicKeyCredentialDescriptorJSON['transports'] } : {}),
  }));

  const options: PublicKeyCredentialCreationOptionsJSON = {
    rp: input.rpId ? { name: input.rpName, id: input.rpId } : { name: input.rpName },
    user: {
      id: toBase64Url(input.user.id),
      name: input.user.name,
      displayName: input.user.displayName,
    },
    challenge: toBase64Url(challenge),
    pubKeyCredParams: [...DEFAULT_PUB_KEY_CRED_PARAMS],
    timeout: input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    excludeCredentials: exclude,
    authenticatorSelection,
    attestation: input.attestation ?? DEFAULT_ATTESTATION,
    ...(input.extensions ? { extensions: input.extensions } : {}),
  };

  return { options, challenge };
}
