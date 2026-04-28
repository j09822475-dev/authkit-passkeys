import { PasskeyError } from '../../errors/base.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'android-key'` attestation — out of MVP scope. Full verification requires
 * parsing the Android Key Attestation extension. Roadmap: v0.3.
 *
 * @throws {PasskeyError}  Code `'unsupported-attestation-format'` always.
 */
export const verifyAndroidKeyAttestation: AttestationVerifier = async () => {
  throw new PasskeyError(
    'unsupported-attestation-format',
    "Attestation format 'android-key' is not supported in v0.1.",
    { details: { attestationFormat: 'android-key' } },
  );
};
