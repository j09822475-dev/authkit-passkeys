import { UnsupportedAttestationFormatError } from '../../errors/classes.js';
import type { ParsedAttestationObject } from '../../types/parsed.js';
import type { AttestationFormat } from '../../types/webauthn.js';
import { verifyNoneAttestation } from './none.js';
import { verifyPackedAttestation } from './packed.js';
import type {
  AttestationVerificationContext,
  AttestationVerificationResult,
  AttestationVerifier,
} from './types.js';

export type { AttestationVerificationContext, AttestationVerificationResult, AttestationVerifier };
export { verifyNoneAttestation } from './none.js';
export { verifyPackedAttestation } from './packed.js';

/**
 * Default verifier registry: only formats shipped in the default bundle (`none`
 * and `packed`) are statically registered. Other formats are loaded via
 * dynamic import the first time the dispatcher sees them — see
 * {@link verifyAttestation}.
 */
export const DEFAULT_ATTESTATION_VERIFIERS: ReadonlyMap<AttestationFormat, AttestationVerifier> =
  new Map<AttestationFormat, AttestationVerifier>([
    ['none', verifyNoneAttestation],
    ['packed', verifyPackedAttestation],
  ]);

/**
 * Dynamically-loaded format → loader map. Each loader returns the format's
 * verifier; the import is a separate chunk so the default bundle does not
 * pay the cost.
 */
const DYNAMIC_LOADERS: Readonly<Record<string, () => Promise<AttestationVerifier>>> = {
  'fido-u2f': () => import('./fido-u2f.js').then((m) => m.verifyFidoU2fAttestation),
  apple: () => import('./apple.js').then((m) => m.verifyAppleAttestation),
  tpm: () => import('./tpm.js').then((m) => m.verifyTpmAttestation),
  'android-key': () => import('./android-key.js').then((m) => m.verifyAndroidKeyAttestation),
};

/**
 * Dispatch attestation verification by `fmt`. Static formats (`none`,
 * `packed`) resolve synchronously through the default registry; the rest are
 * lazy-imported via {@link DYNAMIC_LOADERS} so the default bundle stays small
 * (PLAN §6).
 *
 * @param attestation   Parsed attestation object.
 * @param ctx           Verifier context (clientDataHash).
 * @param overrides     Optional verifier overrides — short-circuits the registry
 *                      and dynamic import. Useful for tests and enterprise opt-ins.
 * @returns             {@link AttestationVerificationResult}.
 * @throws {UnsupportedAttestationFormatError}  When the `fmt` is not registered.
 *
 * @example
 *   const r = await verifyAttestation(att, { clientDataHash });
 */
export async function verifyAttestation(
  attestation: ParsedAttestationObject,
  ctx: AttestationVerificationContext,
  overrides?: ReadonlyMap<string, AttestationVerifier>,
): Promise<AttestationVerificationResult> {
  const override = overrides?.get(attestation.fmt);
  if (override) return override(attestation, ctx);

  const staticVerifier = DEFAULT_ATTESTATION_VERIFIERS.get(attestation.fmt as AttestationFormat);
  if (staticVerifier) return staticVerifier(attestation, ctx);

  const loader = DYNAMIC_LOADERS[attestation.fmt];
  if (!loader) {
    throw new UnsupportedAttestationFormatError(
      `Attestation format "${attestation.fmt}" is not supported.`,
      { details: { attestationFormat: attestation.fmt } },
    );
  }
  const verifier = await loader();
  return verifier(attestation, ctx);
}
