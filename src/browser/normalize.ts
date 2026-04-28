import { toBase64Url } from '../core/encoding/base64url.js';
import type {
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorTransport,
  Base64Url,
  PasskeyExtensionResultsJSON,
  RegistrationResponseJSON,
} from '../types/webauthn.js';

/**
 * Shape a native `PublicKeyCredential` (registration result) into a
 * JSON-safe {@link RegistrationResponseJSON} that can be POSTed back to the
 * server unchanged. All `ArrayBuffer` fields become base64url strings.
 *
 * @param credential  The credential returned by `navigator.credentials.create`.
 * @returns           JSON-safe registration response.
 */
export function normalizeRegistrationResponse(
  credential: PublicKeyCredential,
): RegistrationResponseJSON {
  const response = credential.response as AuthenticatorAttestationResponse & {
    getTransports?: () => string[];
  };

  const transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
  const transportsTyped = transports.filter(isTransport);

  const out: RegistrationResponseJSON = {
    id: credential.id as Base64Url,
    rawId: toBase64Url(new Uint8Array(credential.rawId)),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(new Uint8Array(response.clientDataJSON)),
      attestationObject: toBase64Url(new Uint8Array(response.attestationObject)),
      ...(transportsTyped.length ? { transports: transportsTyped } : {}),
    },
    clientExtensionResults: normalizeExtensions(credential.getClientExtensionResults()),
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment as AuthenticatorAttachment;
  }
  return out;
}

/**
 * Shape a native `PublicKeyCredential` (authentication result) into a
 * JSON-safe {@link AuthenticationResponseJSON}.
 *
 * @param credential  The credential returned by `navigator.credentials.get`.
 * @returns           JSON-safe authentication response.
 */
export function normalizeAuthenticationResponse(
  credential: PublicKeyCredential,
): AuthenticationResponseJSON {
  const response = credential.response as AuthenticatorAssertionResponse;

  const out: AuthenticationResponseJSON = {
    id: credential.id as Base64Url,
    rawId: toBase64Url(new Uint8Array(credential.rawId)),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(new Uint8Array(response.clientDataJSON)),
      authenticatorData: toBase64Url(new Uint8Array(response.authenticatorData)),
      signature: toBase64Url(new Uint8Array(response.signature)),
      ...(response.userHandle
        ? { userHandle: toBase64Url(new Uint8Array(response.userHandle)) }
        : {}),
    },
    clientExtensionResults: normalizeExtensions(credential.getClientExtensionResults()),
  };
  if (credential.authenticatorAttachment) {
    out.authenticatorAttachment = credential.authenticatorAttachment as AuthenticatorAttachment;
  }
  return out;
}

function isTransport(t: string): t is AuthenticatorTransport {
  return t === 'internal' || t === 'hybrid' || t === 'usb' || t === 'nfc' || t === 'ble';
}

function normalizeExtensions(
  results: AuthenticationExtensionsClientOutputs,
): PasskeyExtensionResultsJSON {
  const out: PasskeyExtensionResultsJSON = {};
  if (typeof results.appid === 'boolean') out.appid = results.appid;
  // `appidExclude` is on `AuthenticationExtensionsClientOutputsJSON`; not all
  // DOM lib versions carry it on the synchronous outputs type, so we read defensively.
  const r = results as { appidExclude?: boolean; credProps?: { rk?: boolean } };
  if (typeof r.appidExclude === 'boolean') out.appidExclude = r.appidExclude;
  if (r.credProps) out.credProps = { ...(r.credProps.rk !== undefined ? { rk: r.credProps.rk } : {}) };
  return out;
}
