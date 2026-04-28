import { UnsupportedAttestationFormatError } from '../../errors/classes.js';
import type { AttestationVerifier } from './types.js';

/**
 * `'fido-u2f'` legacy attestation — out of MVP scope. Full verification
 * requires checking the U2F signature over
 * `0x00 || rpIdHash || clientDataHash || credentialId || pubKey`. Until that
 * lands, the verifier rejects rather than rubber-stamps so a malformed U2F
 * attestation cannot be silently accepted.
 *
 * Loaded via dynamic import.
 *
 * @throws {UnsupportedAttestationFormatError}  Always.
 */
export const verifyFidoU2fAttestation: AttestationVerifier = async () => {
  throw new UnsupportedAttestationFormatError(
    "Attestation format 'fido-u2f' is not supported in v0.1.",
    { details: { attestationFormat: 'fido-u2f' } },
  );
};
