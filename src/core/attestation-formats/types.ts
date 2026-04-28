import type { ParsedAttestationObject } from '../../types/ceremony.js';

export interface AttestationVerificationContext {
  /** SHA-256 of the `clientDataJSON` bytes — needed for fmt verifiers that hash signed data themselves. */
  readonly clientDataHash: Uint8Array;
}

export interface AttestationVerificationResult {
  readonly valid: boolean;
  readonly attestationType: 'none' | 'self' | 'basic' | 'attca' | 'anonca' | 'ecdaa' | 'unsupported';
  /** X.509 trust chain (DER bytes) when present — caller may pass to MDS3 for further policy. */
  readonly trustChain?: readonly Uint8Array[];
}

/** Verifier signature implemented by every entry in `attestation-formats/`. */
export type AttestationVerifier = (
  attestation: ParsedAttestationObject,
  context: AttestationVerificationContext,
) => Promise<AttestationVerificationResult>;
