import { UnsupportedAttestationFormatError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'apple'` anonymous attestation — out of MVP scope. Full verification
 * requires the hand-rolled X.509 SPKI walker, the Apple-WebAuthn-Root chain
 * check, and the nonce-extension OID compare described in PLAN §6.4. Until
 * that lands, the verifier rejects rather than rubber-stamps so a malformed
 * Apple attestation cannot be silently accepted.
 *
 * Loaded via dynamic import.
 *
 * @throws {UnsupportedAttestationFormatError}  Always.
 */
export const verifyAppleAttestation: AttestationVerifier = async () => {
  throw new UnsupportedAttestationFormatError(
    "Attestation format 'apple' is not supported in v0.1.",
    { details: { attestationFormat: 'apple' } },
  );
};
