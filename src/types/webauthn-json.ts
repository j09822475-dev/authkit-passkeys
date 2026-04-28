import type { AuthenticatorTransport } from './transport.js';

/**
 * Library-owned mirror of the WebAuthn JSON shapes (no `lib.dom.d.ts` leakage on
 * the server boundary). Field names match the WebAuthn JSON-encoding extension
 * (`PublicKeyCredentialCreationOptionsJSON`, `RegistrationResponseJSON`).
 */

export type COSEAlgorithmIdentifier = number;

export type AttestationConveyancePreference = 'none' | 'indirect' | 'direct' | 'enterprise';

export type AuthenticatorAttachment = 'platform' | 'cross-platform';

export type ResidentKeyRequirement = 'required' | 'preferred' | 'discouraged';

export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

export interface AuthenticatorSelectionCriteria {
  authenticatorAttachment?: AuthenticatorAttachment;
  residentKey?: ResidentKeyRequirement;
  requireResidentKey?: boolean;
  userVerification?: UserVerificationRequirement;
}

/**
 * Library-owned extension input — explicit shape so we never leak
 * `AuthenticationExtensionsClientInputs` (DOM-typed) onto the server boundary.
 */
export interface PasskeyExtensionsInput {
  /** WebAuthn Level 3 PRF extension. */
  prf?: {
    eval?: { first: string; second?: string };
    evalByCredential?: Record<string, { first: string; second?: string }>;
  };
  /** Hint for the client to surface credProps in the response. */
  credProps?: boolean;
  /** Large-blob extension (write/read mode). */
  largeBlob?: { support?: 'required' | 'preferred'; read?: boolean; write?: string };
  /** Free-form pass-through for less-common extensions. */
  [extension: string]: unknown;
}

export interface PasskeyExtensionsOutput {
  prf?: { enabled?: boolean; results?: { first?: string; second?: string } };
  credProps?: { rk?: boolean };
  largeBlob?: { supported?: boolean; written?: boolean; blob?: string };
  [extension: string]: unknown;
}

export interface PublicKeyCredentialDescriptorJSON {
  id: string;
  type: 'public-key';
  transports?: AuthenticatorTransport[];
}

export interface PublicKeyCredentialUserEntityJSON {
  /** base64url-encoded user handle (binary, up to 64 bytes). */
  id: string;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialRpEntity {
  name: string;
  id?: string;
}

export interface PublicKeyCredentialParameters {
  type: 'public-key';
  alg: COSEAlgorithmIdentifier;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntityJSON;
  /** base64url-encoded challenge bytes. */
  challenge: string;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: PasskeyExtensionsInput;
  hints?: Array<'security-key' | 'client-device' | 'hybrid'>;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  /** base64url-encoded challenge bytes. */
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: PasskeyExtensionsInput;
  hints?: Array<'security-key' | 'client-device' | 'hybrid'>;
}

export interface AuthenticatorAttestationResponseJSON {
  clientDataJSON: string;
  attestationObject: string;
  /** Authenticator-supplied transports — use to populate CredentialRecord. */
  transports?: AuthenticatorTransport[];
  /** Native helper output (Level 3) — often absent. */
  authenticatorData?: string;
  /** Native helper output (Level 3) — often absent. */
  publicKey?: string;
  publicKeyAlgorithm?: COSEAlgorithmIdentifier;
}

export interface AuthenticatorAssertionResponseJSON {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  /** base64url-encoded user handle, or omitted for non-discoverable flows. */
  userHandle?: string;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: AuthenticatorAttestationResponseJSON;
  clientExtensionResults: PasskeyExtensionsOutput;
  authenticatorAttachment?: AuthenticatorAttachment;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: AuthenticatorAssertionResponseJSON;
  clientExtensionResults: PasskeyExtensionsOutput;
  authenticatorAttachment?: AuthenticatorAttachment;
}

/** Branded primitive — opaque token returned by `RelyingParty.startRegistration`. */
export type ChallengeToken = string & { readonly __brand: 'ChallengeToken' };

/** Branded primitive — base64url-encoded credential identifier. */
export type CredentialId = string & { readonly __brand: 'CredentialId' };
