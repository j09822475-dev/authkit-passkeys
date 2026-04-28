export type { AuthenticatorTransport } from './transport.js';
export { ALL_TRANSPORTS } from './transport.js';
export type { AuthenticatorFlags } from './flags.js';
export type {
  AttestationConveyancePreference,
  AuthenticatorAssertionResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorAttestationResponseJSON,
  AuthenticatorSelectionCriteria,
  AuthenticationResponseJSON,
  COSEAlgorithmIdentifier,
  ChallengeToken,
  CredentialId,
  PasskeyExtensionsInput,
  PasskeyExtensionsOutput,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptionsJSON,
  PublicKeyCredentialRpEntity,
  PublicKeyCredentialUserEntityJSON,
  RegistrationResponseJSON,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from './webauthn-json.js';
export type { CredentialRecord, AuthenticatedCredential } from './credential.js';
export type {
  AuthenticatorPolicy,
  AuthenticatorPolicyOverride,
  RpConfigOverride,
} from './policy.js';
export type {
  ParsedAttestationObject,
  ParsedAuthenticatorData,
  ParsedClientData,
  ParsedCoseKey,
} from './ceremony.js';
