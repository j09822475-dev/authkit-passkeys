export {
  generateRegistrationOptions,
  type GenerateRegistrationInput,
} from './generate-registration-options.js';
export {
  generateAuthenticationOptions,
  type GenerateAuthenticationInput,
} from './generate-authentication-options.js';
export {
  verifyRegistration,
  type VerifyRegistrationInput,
} from './verify-registration.js';
export {
  verifyAuthentication,
  type VerifyAuthenticationInput,
} from './verify-authentication.js';

export {
  issueChallenge,
  verifyChallenge,
  type CeremonyKind,
} from './challenge.js';

export {
  DEFAULT_ATTESTATION_VERIFIERS,
  verifyAttestation,
  verifyNoneAttestation,
  verifyPackedAttestation,
  type AttestationVerificationContext,
  type AttestationVerificationResult,
  type AttestationVerifier,
} from './attestation/index.js';

export { assertAaguidAllowed } from './policy/aaguid.js';
export { assertUserVerification } from './policy/user-verification.js';

export {
  DEFAULT_CHALLENGE_BYTES,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_PUB_KEY_CRED_ALG_NAMES,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_USER_VERIFICATION,
  MAX_CHALLENGE_TTL_MS,
  MIN_CHALLENGE_TTL_MS,
} from './defaults.js';
