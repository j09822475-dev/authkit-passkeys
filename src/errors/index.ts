export {
  ERROR_MESSAGES,
  FALLBACK_REASONS,
  type PasskeyErrorCode,
  type PasskeyInternalReason,
} from './codes.js';
export { PasskeyError, type PasskeyErrorDetails } from './base.js';
export { PasskeyClientError, mapDomExceptionToClientError } from './client.js';
export { PasskeyVerificationError } from './verification.js';
export { PasskeyPolicyError } from './policy.js';
export { PasskeyInternalError } from './internal.js';
