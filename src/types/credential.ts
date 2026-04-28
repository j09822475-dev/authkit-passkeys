import type { COSEAlgorithmIdentifier } from './webauthn-json.js';
import type { AuthenticatorTransport } from './transport.js';

/**
 * What `RelyingParty.finishRegistration` returns and what callers persist via
 * `CredentialStore.save(record)`.
 *
 * The whole record is the source of truth for re-authentication. Persist all
 * fields — losing `signCount` / `signCountStatic` re-opens replay-detection
 * holes; losing `aaguid` breaks downstream MDS3 policies.
 */
export interface CredentialRecord {
  /** base64url-encoded credential identifier (matches WebAuthn `id`). */
  credentialId: string;
  /**
   * Canonical user handle bytes (up to 64). NEVER lossily decoded to UTF-8 —
   * binary user IDs (e.g. random 32-byte tokens) round-trip exactly.
   */
  userId: Uint8Array;
  /** SPKI-encoded public key — re-importable via `crypto.subtle.importKey`. */
  publicKey: Uint8Array;
  /** COSE algorithm identifier (e.g. -7 = ES256, -257 = RS256, -8 = EdDSA). */
  publicKeyAlgorithm: COSEAlgorithmIdentifier;
  /** Latest sign-counter the authenticator has reported. */
  signCount: number;
  /**
   * `true` iff this authenticator is known to always return `signCount === 0`
   * (iCloud Keychain, Google Password Manager, etc.). `null` until the first
   * authentication observes a counter; flipped to `true` on a 0-counter assertion
   * and `false` on a non-zero one. Policy code skips the "counter must increase"
   * check when `signCountStatic === true`.
   */
  signCountStatic: boolean | null;
  transports: AuthenticatorTransport[];
  /** Hex-formatted UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). */
  aaguid: string;
  backupEligible: boolean;
  backupState: boolean;
  attestationFormat: string;
  createdAt: Date;
}

/**
 * What `RelyingParty.finishAuthentication` resolves to on success. The caller
 * MUST persist the new sign-counter (and `signCountStatic` if it changed)
 * atomically with session creation.
 */
export interface AuthenticatedCredential {
  credentialId: string;
  userId: Uint8Array;
  /** Counter reported by THIS assertion — caller persists via `updateSignCount`. */
  newSignCount: number;
  /** `true` if the credential was observed to be static this round. */
  signCountStatic: boolean;
  /** Echoed from the credential record — handy for downstream session metadata. */
  aaguid: string;
  /** Backup state observed in this assertion — store it. */
  backupState: boolean;
  /** Backup eligibility observed in this assertion (immutable; should match record). */
  backupEligible: boolean;
  /** Optional client-extension outputs (PRF results, etc.). */
  extensionResults?: Record<string, unknown>;
}
