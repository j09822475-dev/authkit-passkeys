import type { AaguidString, AuthenticatorTransport, Base64Url } from './webauthn.js';

/**
 * The persisted credential shape. Branded with the caller's `TUserId` so
 * lookups type-check end-to-end.
 *
 * Storage adapters MUST round-trip every field — losing `aaguid` breaks
 * downstream MDS3 policies, losing `counter` re-opens replay-detection holes,
 * losing `backupState` breaks the BS-bit observability the audit hook
 * surfaces.
 */
export interface CredentialRecord<TUserId extends string = string> {
  /** WebAuthn credential ID, base64url-encoded. */
  credentialId: Base64Url;
  /** Owner of this credential. */
  userId: TUserId;
  /**
   * Stored COSE public key, base64url-encoded. Decoded internally via
   * `parseCoseKey` for verification — the SQL column is opaque.
   */
  publicKey: Base64Url;
  /** Authenticator model identifier (16-byte UUID, dashed). */
  aaguid: AaguidString;
  /** Last observed signature counter. 0 is legitimate for sync passkeys (PLAN §9.6). */
  counter: number;
  /**
   * Authenticator-reported transports (`internal`, `hybrid`, `usb`, `nfc`, `ble`).
   * Used to populate `allowCredentials.transports` so subsequent ceremonies
   * pick the right UI prompt.
   */
  transports: ReadonlyArray<AuthenticatorTransport>;
  /** BE bit — this credential CAN be backed up / synced (multi-device). */
  backupEligible: boolean;
  /** BS bit — this credential IS currently backed up. Mutates over a credential's lifetime. */
  backupState: boolean;
  /** Derived from `backupEligible`. Stored explicitly so DB queries don't recompute. */
  deviceType: 'singleDevice' | 'multiDevice';
  /** First successful registration timestamp (epoch ms). */
  createdAt: number;
  /** Last successful authentication timestamp (epoch ms). */
  lastUsedAt: number | null;
}

/**
 * What `verifyRegistration` returns. The caller fills `userId` (and may
 * accept the defaults for `createdAt` / `lastUsedAt`) before passing to
 * `store.create`. The library does NOT touch the store automatically — the
 * call site owns the transaction boundary.
 */
export type NewCredentialRecord<TUserId extends string = string> = Omit<
  CredentialRecord<TUserId>,
  'userId' | 'createdAt' | 'lastUsedAt'
> & {
  /** Fill before passing to `store.create`. */
  userId?: TUserId;
};

/**
 * Audit/logging payload fired by `verifyRegistration.onVerified`. Server-side
 * only — the granular `attestationFormat` and `aaguid` are useful for fraud
 * scoring but should never be forwarded to the browser.
 */
export interface RegistrationVerifiedEvent {
  credentialId: Base64Url;
  aaguid: AaguidString;
  attestationFormat: string;
  transports: ReadonlyArray<AuthenticatorTransport>;
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  /** Whether the credential is sync-eligible (BE bit). */
  backupEligible: boolean;
  /** Whether the credential is currently synced/backed up (BS bit). */
  backupState: boolean;
  /** Derived from BE: `'multiDevice'` if BE=1, else `'singleDevice'`. */
  deviceType: 'singleDevice' | 'multiDevice';
}

/** Audit/logging payload fired by `verifyAuthentication.onVerified`. */
export interface AuthenticationVerifiedEvent<TUserId extends string = string> {
  userId: TUserId;
  credentialId: Base64Url;
  /** Strictly-greater counter value, or 0 when the authenticator is signCount-static. */
  newCounter: number;
  flags: { up: boolean; uv: boolean; be: boolean; bs: boolean };
  /** True when the stored BS bit just flipped 0→1 (credential just got backed up). */
  newlyBackedUp: boolean;
}

/** Successful authentication payload returned to the call site. */
export interface VerifiedAuthentication<TUserId extends string = string> {
  /** The user owning the credential. */
  userId: TUserId;
  /** The credential that was used. `counter` is the NEW value to persist. */
  credential: CredentialRecord<TUserId>;
  /** Updated counter — call `store.updateCounter(credentialId, newCounter)` after your tx commits. */
  newCounter: number;
  /** True when WebAuthn `flags.uv` was set. */
  userVerified: boolean;
}
