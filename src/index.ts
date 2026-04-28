/**
 * `@authkit/passkeys` root barrel — exposes the stable error contract, the
 * library version, and types-only re-exports. Consumers should import from
 * subpaths (`/browser`, `/server`, `/storage/*`) for the actual ceremony
 * code so tree-shaking can drop the side they don't use.
 */

export { version } from './core/version.js';

export {
  AaguidNotAllowedError,
  AuthenticationFailedError,
  CounterRegressionError,
  ERROR_MESSAGES,
  FALLBACK_CODES,
  InternalError,
  InvalidAttestationError,
  InvalidChallengeError,
  InvalidChallengeTokenError,
  InvalidOriginError,
  InvalidRpIdError,
  InvalidStateError,
  NotSupportedError,
  PasskeyError,
  SecurityError,
  StorageError,
  TimeoutError,
  UnsupportedAlgorithmError,
  UnsupportedAttestationFormatError,
  UserCancelledError,
  UserVerificationRequiredError,
  WrongCeremonyError,
  isPasskeyError,
  type PasskeyErrorCode,
  type PasskeyErrorDetails,
  type PasskeyInternalReason,
} from './errors/index.js';

export type {
  AaguidPolicy,
  AaguidString,
  AttestationConveyancePreference,
  AttestationFormat,
  AuthenticationOptionsJSON,
  AuthenticationResponseJSON,
  AuthenticationVerifiedEvent,
  AuthenticatorAttachment,
  AuthenticatorFlags,
  AuthenticatorTransport,
  Base64Url,
  ChallengeSigningKeys,
  ChallengeToken,
  CoseAlgId,
  CoseAlgName,
  CredentialRecord,
  NewCredentialRecord,
  PasskeyExtensionInputsJSON,
  PasskeyExtensionResultsJSON,
  RegistrationOptionsJSON,
  RegistrationResponseJSON,
  RegistrationVerifiedEvent,
  ResidentKeyRequirement,
  UserVerificationRequirement,
  VerifiedAuthentication,
} from './types/index.js';
