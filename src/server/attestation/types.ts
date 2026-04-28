import type { ParsedAttestationObject } from '../../types/parsed.js';

/** Context passed to every attestation verifier. */
export interface AttestationVerificationContext {
  /** SHA-256 of the `clientDataJSON` bytes — needed for fmt verifiers that hash signed data themselves. */
  readonly clientDataHash: Uint8Array;
}

/** Result returned by every attestation verifier. */
export interface AttestationVerificationResult {
  readonly valid: boolean;
  readonly attestationType: 'none' | 'self' | 'basic' | 'attca' | 'anonca' | 'unsupported';
  /** X.509 trust chain (DER bytes) when present — caller may pass to MDS3 for further policy. */
  readonly trustChain?: ReadonlyArray<Uint8Array>;
}

/** The verifier signature implemented by every entry in `attestation/`. */
export type AttestationVerifier = (
  attestation: ParsedAttestationObject,
  context: AttestationVerificationContext,
) => Promise<AttestationVerificationResult>;
