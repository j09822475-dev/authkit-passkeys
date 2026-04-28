import { UnsupportedAttestationFormatError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'android-key'` attestation — out of MVP scope. Full verification requires
 * parsing the Android Key Attestation extension. Roadmap: v0.3.
 *
 * Loaded via dynamic import.
 *
 * @throws {UnsupportedAttestationFormatError}  Always.
 */
export const verifyAndroidKeyAttestation: AttestationVerifier = async () => {
  throw new UnsupportedAttestationFormatError(
    "Attestation format 'android-key' is not supported in v0.1.",
    { details: { attestationFormat: 'android-key' } },
  );
};
