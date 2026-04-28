import type { AuthenticatorFlags, CoseAlgId } from './webauthn.js';

/**
 * Decoded `authData` segment of a WebAuthn authenticator-data buffer.
 */
export interface ParsedAuthenticatorData {
  /** SHA-256 hash of the RP-ID the authenticator signed against (32 bytes). */
  readonly rpIdHash: Uint8Array;
  readonly flags: AuthenticatorFlags;
  /** Unsigned 32-bit sign-counter (big-endian). */
  readonly signCount: number;
  /** Present iff `flags.at` (attested credential data is present, i.e. registration). */
  readonly attestedCredentialData?: {
    readonly aaguid: Uint8Array;
    readonly credentialId: Uint8Array;
    /** Raw COSE-key bytes (still CBOR-encoded). */
    readonly credentialPublicKey: Uint8Array;
  };
  /** Present iff `flags.ed`. Raw CBOR-encoded extension map. */
  readonly extensions?: Uint8Array;
  /** Original byte slice — kept verbatim for signature verification. */
  readonly raw: Uint8Array;
}

/**
 * Decoded attestation object parsed during registration.
 */
export interface ParsedAttestationObject {
  readonly fmt: string;
  readonly authData: ParsedAuthenticatorData;
  /** Raw attestation statement; format-specific verifier consumes it. */
  readonly attStmt: Record<string, unknown>;
  /** Raw `authData` byte slice — kept verbatim for fmt verifiers that hash signed data themselves. */
  readonly rawAuthData: Uint8Array;
}

/** Result of parsing & validating a `clientDataJSON` segment. */
export interface ParsedClientData {
  readonly type: string;
  readonly challenge: string;
  readonly origin: string;
  readonly crossOrigin: boolean | undefined;
  readonly tokenBinding: { readonly status: string; readonly id?: string } | undefined;
  /** Original raw bytes — hash THESE, never re-stringify. */
  readonly raw: Uint8Array;
}

/** Decoded COSE key (RFC 8152 Key_ops + algorithm + algorithm-specific parameters). */
export interface ParsedCoseKey {
  readonly kty: number;
  readonly alg: CoseAlgId;
  /** EC2 / OKP curve identifier (where applicable). */
  readonly crv?: number;
  /** EC2/OKP x-coordinate. */
  readonly x?: Uint8Array;
  /** EC2 y-coordinate. */
  readonly y?: Uint8Array;
  /** RSA public exponent. */
  readonly e?: Uint8Array;
  /** RSA modulus. */
  readonly n?: Uint8Array;
}
