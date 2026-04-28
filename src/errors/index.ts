export {
  ERROR_MESSAGES,
  FALLBACK_CODES,
  type PasskeyErrorCode,
  type PasskeyInternalReason,
} from './codes.js';
export { PasskeyError, isPasskeyError, type PasskeyErrorDetails } from './base.js';
export {
  NotSupportedError,
  UserCancelledError,
  TimeoutError,
  InvalidStateError,
  SecurityError,
  InvalidChallengeTokenError,
  WrongCeremonyError,
  InvalidChallengeError,
  InvalidOriginError,
  InvalidRpIdError,
  AuthenticationFailedError,
  InvalidAttestationError,
  UnsupportedAlgorithmError,
  UnsupportedAttestationFormatError,
  CounterRegressionError,
  UserVerificationRequiredError,
  AaguidNotAllowedError,
  StorageError,
  InternalError,
} from './classes.js';
