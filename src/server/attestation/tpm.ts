import { UnsupportedAttestationFormatError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'tpm'` attestation — out of MVP scope. Full verification requires parsing
 * `TPMS_ATTEST` + `TPMT_PUBLIC` structures. Roadmap: v0.3.
 *
 * Loaded via dynamic import.
 *
 * @throws {UnsupportedAttestationFormatError}  Always.
 */
export const verifyTpmAttestation: AttestationVerifier = async () => {
  throw new UnsupportedAttestationFormatError(
    "Attestation format 'tpm' is not supported in v0.1.",
    { details: { attestationFormat: 'tpm' } },
  );
};
