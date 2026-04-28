import { PasskeyError } from '../../errors/base.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'tpm'` attestation — out of MVP scope. Full verification requires parsing
 * TPMS_ATTEST + TPMT_PUBLIC structures. Roadmap: v0.3.
 *
 * @throws {PasskeyError}  Code `'unsupported-attestation-format'` always.
 */
export const verifyTpmAttestation: AttestationVerifier = async () => {
  throw new PasskeyError(
    'unsupported-attestation-format',
    "Attestation format 'tpm' is not supported in v0.1.",
    { details: { attestationFormat: 'tpm' } },
  );
};
