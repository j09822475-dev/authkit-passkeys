/**
 * Branded primitive — base64url-encoded byte string. Constructable only via
 * `toBase64Url(Uint8Array)` or `assertBase64Url(string)`. ESLint forbids
 * `as Base64Url` casts in app code.
 */
declare const __base64Url: unique symbol;
export type Base64Url = string & { readonly [__base64Url]: void };

/**
 * Branded primitive — canonical UUID-formatted authenticator AAGUID
 * (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
 */
declare const __aaguid: unique symbol;
export type AaguidString = string & { readonly [__aaguid]: void };

/**
 * Branded primitive — short-lived signed envelope passed between
 * `generate*Options` and `verify*`. Named `ChallengeToken` (not
 * `SessionToken`) because "session" is universally taken in auth land for the
 * authenticated-user session. This token has nothing to do with that — it is
 * a stateless, ceremony-scoped HMAC envelope.
 */
declare const __challengeToken: unique symbol;
export type ChallengeToken = string & { readonly [__challengeToken]: void };

/**
 * WebAuthn transport hint. Spec values per WebAuthn Level 3.
 *
 * - `internal` — built-in platform authenticator (Touch ID, Face ID, Windows Hello)
 * - `hybrid`   — cross-device QR-code / caBLE flow (phone-as-authenticator)
 * - `usb`      — USB-attached roaming authenticator (YubiKey, Titan)
 * - `nfc`      — NFC-attached roaming authenticator
 * - `ble`      — Bluetooth-attached roaming authenticator
 */
export type AuthenticatorTransport = 'internal' | 'hybrid' | 'usb' | 'nfc' | 'ble';

export const ALL_TRANSPORTS: readonly AuthenticatorTransport[] = [
  'internal',
  'hybrid',
  'usb',
  'nfc',
  'ble',
];

export type AuthenticatorAttachment = 'platform' | 'cross-platform';
export type ResidentKeyRequirement = 'required' | 'preferred' | 'discouraged';
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';
export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct' | 'enterprise';

/** COSE algorithm name → identifier mapping. */
export type CoseAlgName = 'ES256' | 'ES384' | 'ES512' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512' | 'PS256';

/** COSE algorithm identifier (signed integer, see IANA COSE registry). */
export type CoseAlgId = number;

/** Attestation `fmt` values defined by the WebAuthn registry. */
export type AttestationFormat =
  | 'none'
  | 'packed'
  | 'fido-u2f'
  | 'apple'
  | 'tpm'
  | 'android-key';

/**
 * Decoded authenticator-data flag byte.
 * @see https://www.w3.org/TR/webauthn-3/#authenticator-data
 */
export interface AuthenticatorFlags {
  /** UP — User Present (touch / button / proximity). */
  readonly up: boolean;
  /** UV — User Verified (PIN / biometric). */
  readonly uv: boolean;
  /** BE — Backup Eligible. May be set on first observation; cannot regress 1 → 0. */
  readonly be: boolean;
  /** BS — Backup State (currently backed up). May flip both ways. */
  readonly bs: boolean;
  /** AT — Attested credential data is present. */
  readonly at: boolean;
  /** ED — Extension data is present. */
  readonly ed: boolean;
}

/**
 * Library-owned mirror of the WebAuthn-JSON extension-results shape. Hand-narrowed
 * to the extensions the library actually plumbs through, so we don't leak the
 * full DOM-typed `AuthenticationExtensionsClientOutputsJSON` into a server
 * module that runs on Workers / Vercel Edge / Deno without the DOM lib.
 */
export interface PasskeyExtensionResultsJSON {
  appid?: boolean;
  appidExclude?: boolean;
  credProps?: { rk?: boolean };
  largeBlob?: { supported?: boolean; blob?: Base64Url; written?: boolean };
  prf?: { enabled?: boolean; results?: { first?: Base64Url; second?: Base64Url } };
}

/** Library-owned mirror of the WebAuthn-JSON extension-input shape. */
export interface PasskeyExtensionInputsJSON {
  credProps?: boolean;
  largeBlob?: { support?: 'required' | 'preferred'; read?: boolean; write?: Base64Url };
  prf?: {
    eval?: { first: Base64Url; second?: Base64Url };
    evalByCredential?: Record<string, { first: Base64Url; second?: Base64Url }>;
  };
}

/* ---------- Server → Browser: options shapes ---------- */

export interface PublicKeyCredentialRpEntityJSON {
  id: string;
  name: string;
}

export interface PublicKeyCredentialUserEntityJSON {
  /** base64url-encoded user handle (binary, up to 64 bytes). */
  id: Base64Url;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialParametersJSON {
  type: 'public-key';
  alg: CoseAlgId;
}

export interface PublicKeyCredentialDescriptorJSON {
  id: Base64Url;
  type: 'public-key';
  transports?: ReadonlyArray<AuthenticatorTransport>;
}

export interface AuthenticatorSelectionCriteriaJSON {
  authenticatorAttachment?: AuthenticatorAttachment;
  residentKey?: ResidentKeyRequirement;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}

export interface RegistrationOptionsJSON {
  rp: PublicKeyCredentialRpEntityJSON;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64Url;
  pubKeyCredParams: ReadonlyArray<PublicKeyCredentialParametersJSON>;
  timeout?: number;
  excludeCredentials?: ReadonlyArray<PublicKeyCredentialDescriptorJSON>;
  authenticatorSelection?: AuthenticatorSelectionCriteriaJSON;
  attestation?: AttestationConveyancePreference;
  extensions?: PasskeyExtensionInputsJSON;
  hints?: ReadonlyArray<'security-key' | 'client-device' | 'hybrid'>;
}

export interface AuthenticationOptionsJSON {
  challenge: Base64Url;
  timeout?: number;
  rpId?: string;
  allowCredentials?: ReadonlyArray<PublicKeyCredentialDescriptorJSON>;
  userVerification?: UserVerificationRequirement;
  extensions?: PasskeyExtensionInputsJSON;
  hints?: ReadonlyArray<'security-key' | 'client-device' | 'hybrid'>;
}

/* ---------- Browser → Server: response shapes ---------- */

export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: Base64Url;
  attestationObject: Base64Url;
  /** Authenticator-supplied transports — populates `CredentialRecord.transports`. */
  transports?: ReadonlyArray<AuthenticatorTransport>;
  /** Native helper output (Level 3) — often absent. */
  authenticatorData?: Base64Url;
  /** Native helper output (Level 3) — often absent. */
  publicKey?: Base64Url;
  publicKeyAlgorithm?: CoseAlgId;
}

export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: Base64Url;
  authenticatorData: Base64Url;
  signature: Base64Url;
  /** base64url-encoded user handle, or omitted for non-discoverable flows. */
  userHandle?: Base64Url;
}

export interface RegistrationResponseJSON {
  id: Base64Url;
  rawId: Base64Url;
  type: 'public-key';
  response: AuthenticatorAttestationResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment | null;
  clientExtensionResults: PasskeyExtensionResultsJSON;
}

export interface AuthenticationResponseJSON {
  id: Base64Url;
  rawId: Base64Url;
  type: 'public-key';
  response: AuthenticatorAssertionResponseJSON;
  authenticatorAttachment?: AuthenticatorAttachment | null;
  clientExtensionResults: PasskeyExtensionResultsJSON;
}
