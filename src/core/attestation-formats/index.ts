import { verifyNoneAttestation } from './none.js';
import { verifyPackedAttestation } from './packed.js';
import { verifyFidoU2fAttestation } from './fido-u2f.js';
import { verifyAppleAttestation } from './apple.js';
import { verifyAndroidKeyAttestation } from './android-key.js';
import { verifyTpmAttestation } from './tpm.js';
import type { AttestationVerifier } from './types.js';

/**
 * Default attestation-verifier registry. Consumers may pass a customized map
 * to {@link RelyingParty} to override or add formats.
 *
 * Tree-shaking: each verifier is its own module — bundlers drop the ones the
 * consumer's registry doesn't reference.
 */
export const DEFAULT_ATTESTATION_VERIFIERS: ReadonlyMap<string, AttestationVerifier> = new Map<
  string,
  AttestationVerifier
>([
  ['none', verifyNoneAttestation],
  ['packed', verifyPackedAttestation],
  ['fido-u2f', verifyFidoU2fAttestation],
  ['apple', verifyAppleAttestation],
  ['android-key', verifyAndroidKeyAttestation],
  ['tpm', verifyTpmAttestation],
]);

export {
  verifyNoneAttestation,
  verifyPackedAttestation,
  verifyFidoU2fAttestation,
  verifyAppleAttestation,
  verifyAndroidKeyAttestation,
  verifyTpmAttestation,
};
export type { AttestationVerifier, AttestationVerificationContext, AttestationVerificationResult } from './types.js';
