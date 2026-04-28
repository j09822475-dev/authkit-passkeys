import type { CredentialRecord } from '../types/credential.js';

/**
 * User-supplied credential persistence. Callers either implement this or pull
 * a built-in adapter from `@authkit/passkeys/storage/*`.
 *
 * @typeParam TExt  Optional record extension — application-specific metadata
 *                  (e.g. `{ deviceLabel: string }`) is preserved through CRUD.
 *
 * @example
 *   class MyStore implements CredentialStore {
 *     async findById(id) { return db.passkey.findUnique({ where: { id } }); }
 *     async findByUserId(uid) { return db.passkey.findMany({ where: { userId: uid } }); }
 *     async save(rec) { await db.passkey.create({ data: rec }); }
 *     async update(id, patch) { await db.passkey.update({ where: { id }, data: patch }); }
 *     async delete(id) { await db.passkey.delete({ where: { id } }); }
 *   }
 */
export interface CredentialStore<TExt extends Record<string, unknown> = Record<never, never>> {
  /** Look up by credentialId — used during authentication. */
  findById(credentialId: string): Promise<(CredentialRecord & TExt) | null>;
  /** Look up all credentials for a user — used during registration to fill `excludeCredentials`. */
  findByUserId(userId: Uint8Array): Promise<Array<CredentialRecord & TExt>>;
  /** Persist a brand-new credential. MUST reject if `credentialId` already exists. */
  save(record: CredentialRecord & TExt): Promise<void>;
  /**
   * Patch an existing credential's mutable fields (sign-counter, signCountStatic,
   * backup-state) atomically. The library calls this after every successful
   * authentication; persist alongside session creation when possible.
   */
  update(
    credentialId: string,
    patch: Partial<Pick<CredentialRecord, 'signCount' | 'signCountStatic' | 'backupState'>>,
  ): Promise<void>;
  /** Delete a credential (user-initiated revoke). */
  delete(credentialId: string): Promise<void>;
}
