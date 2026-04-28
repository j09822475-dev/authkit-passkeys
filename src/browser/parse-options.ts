import { fromBase64Url } from '../core/encoding/base64url.js';
import type {
  AuthenticationOptionsJSON,
  RegistrationOptionsJSON,
} from '../types/webauthn.js';

/**
 * Decode a server-supplied {@link RegistrationOptionsJSON} into the binary
 * `PublicKeyCredentialCreationOptions` accepted by
 * `navigator.credentials.create`. Polyfill for
 * `PublicKeyCredential.parseCreationOptionsFromJSON()` (not yet shipped in
 * every UA).
 *
 * @param json  Options JSON from the server.
 * @returns     Native creation-options object.
 *
 * @example
 *   const options = parseRegistrationOptions(jsonFromServer);
 *   const cred = await navigator.credentials.create({ publicKey: options });
 */
export function parseRegistrationOptions(
  json: RegistrationOptionsJSON,
): PublicKeyCredentialCreationOptions {
  return {
    rp: json.rp,
    user: {
      id: fromBase64Url(json.user.id),
      name: json.user.name,
      displayName: json.user.displayName,
    },
    challenge: fromBase64Url(json.challenge),
    pubKeyCredParams: json.pubKeyCredParams.map((p) => ({ type: p.type, alg: p.alg })),
    ...(json.timeout !== undefined ? { timeout: json.timeout } : {}),
    ...(json.excludeCredentials
      ? {
          excludeCredentials: json.excludeCredentials.map((c) => ({
            id: fromBase64Url(c.id),
            type: c.type,
            ...(c.transports
              ? { transports: c.transports as unknown as AuthenticatorTransport[] }
              : {}),
          })),
        }
      : {}),
    ...(json.authenticatorSelection ? { authenticatorSelection: json.authenticatorSelection } : {}),
    ...(json.attestation ? { attestation: json.attestation } : {}),
    ...(json.extensions ? { extensions: json.extensions as AuthenticationExtensionsClientInputs } : {}),
  };
}

/**
 * Decode a server-supplied {@link AuthenticationOptionsJSON} into the binary
 * `PublicKeyCredentialRequestOptions` accepted by
 * `navigator.credentials.get`. Polyfill for
 * `PublicKeyCredential.parseRequestOptionsFromJSON()`.
 *
 * @param json  Options JSON from the server.
 * @returns     Native request-options object.
 *
 * @example
 *   const options = parseAuthenticationOptions(jsonFromServer);
 *   const assertion = await navigator.credentials.get({ publicKey: options });
 */
export function parseAuthenticationOptions(
  json: AuthenticationOptionsJSON,
): PublicKeyCredentialRequestOptions {
  return {
    challenge: fromBase64Url(json.challenge),
    ...(json.timeout !== undefined ? { timeout: json.timeout } : {}),
    ...(json.rpId ? { rpId: json.rpId } : {}),
    ...(json.allowCredentials
      ? {
          allowCredentials: json.allowCredentials.map((c) => ({
            id: fromBase64Url(c.id),
            type: c.type,
            ...(c.transports
              ? { transports: c.transports as unknown as AuthenticatorTransport[] }
              : {}),
          })),
        }
      : {}),
    ...(json.userVerification ? { userVerification: json.userVerification } : {}),
    ...(json.extensions ? { extensions: json.extensions as AuthenticationExtensionsClientInputs } : {}),
  };
}
