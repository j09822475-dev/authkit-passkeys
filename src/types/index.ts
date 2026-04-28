export type {
  AaguidString,
  AttestationConveyancePreference,
  AttestationFormat,
  AuthenticationOptionsJSON,
  AuthenticationResponseJSON,
  AuthenticatorAssertionResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorAttestationResponseJSON,
  AuthenticatorFlags,
  AuthenticatorSelectionCriteriaJSON,
  AuthenticatorTransport,
  Base64Url,
  ChallengeToken,
  CoseAlgId,
  CoseAlgName,
  PasskeyExtensionInputsJSON,
  PasskeyExtensionResultsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialParametersJSON,
  PublicKeyCredentialRpEntityJSON,
  PublicKeyCredentialUserEntityJSON,
  RegistrationOptionsJSON,
  RegistrationResponseJSON,
  ResidentKeyRequirement,
  UserVerificationRequirement,
} from './webauthn.js';
export { ALL_TRANSPORTS } from './webauthn.js';

export type {
  AuthenticationVerifiedEvent,
  CredentialRecord,
  NewCredentialRecord,
  RegistrationVerifiedEvent,
  VerifiedAuthentication,
} from './credential.js';

export type { AaguidPolicy, ChallengeSigningKeys } from './options.js';

export type {
  ParsedAttestationObject,
  ParsedAuthenticatorData,
  ParsedClientData,
  ParsedCoseKey,
} from './parsed.js';
