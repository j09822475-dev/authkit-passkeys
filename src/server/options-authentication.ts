import { toBase64Url } from '../core/encoding/base64url.js';
import { randomBytes } from '../core/crypto/random.js';
import type {
  PasskeyExtensionsInput,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '../types/webauthn-json.js';
import type { AuthenticatorPolicy } from '../types/policy.js';
import { DEFAULT_CHALLENGE_BYTES, DEFAULT_TIMEOUT_MS } from './defaults.js';

export interface BuildAuthenticationOptionsInput {
  rpId: string | undefined;
  policy: AuthenticatorPolicy;
  allowCredentials: ReadonlyArray<{ id: string; transports?: readonly string[] }>;
  extensions: PasskeyExtensionsInput | undefined;
  timeoutMs: number;
}

export interface BuildAuthenticationOptionsResult {
  options: PublicKeyCredentialRequestOptionsJSON;
  challenge: Uint8Array;
}

/**
 * Internal helper. Build the `PublicKeyCredentialRequestOptionsJSON` payload
 * the browser will pass to `navigator.credentials.get`. Empty
 * `allowCredentials` triggers the discoverable-credential (passwordless) flow.
 *
 * Not re-exported from `server/index.ts`; consumers go through
 * `RelyingParty.startAuthentication`.
 */
export function _buildAuthenticationOptions(
  input: BuildAuthenticationOptionsInput,
): BuildAuthenticationOptionsResult {
  const challenge = randomBytes(DEFAULT_CHALLENGE_BYTES);
  const allow: PublicKeyCredentialDescriptorJSON[] = input.allowCredentials.map((c) => ({
    id: c.id,
    type: 'public-key',
    ...(c.transports ? { transports: c.transports as PublicKeyCredentialDescriptorJSON['transports'] } : {}),
  }));

  const options: PublicKeyCredentialRequestOptionsJSON = {
    challenge: toBase64Url(challenge),
    timeout: input.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    ...(input.rpId ? { rpId: input.rpId } : {}),
    allowCredentials: allow,
    userVerification: input.policy.userVerification,
    ...(input.extensions ? { extensions: input.extensions } : {}),
  };

  return { options, challenge };
}
