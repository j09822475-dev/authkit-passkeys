import type { Base64Url } from '../types/webauthn.js';
import type {
  CredentialRecord,
  NewCredentialRecord,
} from '../types/credential.js';

export type { CredentialRecord, NewCredentialRecord };

/**
 * Pluggable credential persistence contract.
 *
 * Every storage adapter implements this interface; app code calls these
 * methods, never the underlying ORM directly. The generic `<TUserId>` is
 * plumbed through the rest of the API so credential lookups are type-safe
 * end-to-end.
 *
 * Adapters MUST round-trip every {@link CredentialRecord} field — losing
 * `aaguid` breaks downstream MDS3 policies, losing `counter` re-opens
 * replay-detection holes, losing `backupState` breaks the BS-bit
 * observability the audit hook surfaces.
 *
 * @example
 *   class MyStore implements CredentialStore<UserId> {
 *     async create(rec)         { await db.passkey.create({ data: rec }); return rec; }
 *     async findByCredentialId(id) { return db.passkey.findUnique({ where: { id } }); }
 *     async listByUserId(uid)   { return db.passkey.findMany({ where: { userId: uid } }); }
 *     async updateCounter(id, c){ await db.passkey.update({ where: { id }, data: { counter: c } }); }
 *     async updateBackupState(id, s){ await db.passkey.update({ where: { id }, data: { backupState: s } }); }
 *     async deleteByCredentialId(id) { await db.passkey.delete({ where: { id } }); }
 *   }
 */
export interface CredentialStore<TUserId extends string = string> {
  /** Persist a freshly registered credential. Adapters MUST surface duplicates as `InvalidStateError`. */
  create(record: NewCredentialRecord<TUserId>): Promise<CredentialRecord<TUserId>>;
  /**
   * Look up by credential ID — used during `verifyAuthentication`.
   *
   * MUST run with a constant-time-shape access pattern: returning `null` and
   * returning a record whose signature later fails verification must be
   * indistinguishable to the caller (PLAN §5.6 / §9.10).
   */
  findByCredentialId(credentialId: Base64Url): Promise<CredentialRecord<TUserId> | null>;
  /** All credentials for a user — populates `excludeCredentials` and `allowCredentials`. */
  listByUserId(userId: TUserId): Promise<ReadonlyArray<CredentialRecord<TUserId>>>;
  /** Bump the signature counter post-authentication. MUST be atomic per credential. */
  updateCounter(credentialId: Base64Url, newCounter: number): Promise<void>;
  /** Persist BE/BS state changes after a sync flip (PLAN §9.6). MUST be atomic. */
  updateBackupState(credentialId: Base64Url, backupState: boolean): Promise<void>;
  /** Delete by credential ID — used by /settings UIs. */
  deleteByCredentialId(credentialId: Base64Url): Promise<void>;
}
