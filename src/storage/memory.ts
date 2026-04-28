import { InvalidStateError } from '../errors/classes.js';
import type { Base64Url } from '../types/webauthn.js';
import type { CredentialRecord, NewCredentialRecord } from '../types/credential.js';
import type { CredentialStore } from './types.js';

/**
 * In-memory {@link CredentialStore}. Single-process only — testing /
 * single-instance demos / serverless dev. Production multi-instance deploys
 * MUST implement {@link CredentialStore} on a real database.
 *
 * @typeParam TUserId  Branded user-id type carried through the store.
 *
 * @example
 *   const store = createMemoryCredentialStore<UserId>();
 *   await store.create({ ...record, userId: user.id });
 */
export function createMemoryCredentialStore<TUserId extends string = string>(): CredentialStore<TUserId> {
  const byCredentialId = new Map<string, CredentialRecord<TUserId>>();
  const byUserId = new Map<TUserId, Set<string>>();

  function ensureUserSet(userId: TUserId): Set<string> {
    let set = byUserId.get(userId);
    if (!set) {
      set = new Set();
      byUserId.set(userId, set);
    }
    return set;
  }

  return {
    async create(record: NewCredentialRecord<TUserId>): Promise<CredentialRecord<TUserId>> {
      if (!record.userId) {
        throw new InvalidStateError('CredentialRecord.userId must be set before create.');
      }
      if (byCredentialId.has(record.credentialId)) {
        throw new InvalidStateError(`Credential ${record.credentialId} already exists.`);
      }
      const stored: CredentialRecord<TUserId> = {
        credentialId: record.credentialId,
        userId: record.userId,
        publicKey: record.publicKey,
        aaguid: record.aaguid,
        counter: record.counter,
        transports: record.transports,
        backupEligible: record.backupEligible,
        backupState: record.backupState,
        deviceType: record.deviceType,
        createdAt: Date.now(),
        lastUsedAt: null,
      };
      byCredentialId.set(record.credentialId, stored);
      ensureUserSet(record.userId).add(record.credentialId);
      return stored;
    },

    async findByCredentialId(credentialId: Base64Url): Promise<CredentialRecord<TUserId> | null> {
      return byCredentialId.get(credentialId) ?? null;
    },

    async listByUserId(userId: TUserId): Promise<ReadonlyArray<CredentialRecord<TUserId>>> {
      const ids = byUserId.get(userId);
      if (!ids) return [];
      const out: CredentialRecord<TUserId>[] = [];
      for (const id of ids) {
        const rec = byCredentialId.get(id);
        if (rec) out.push(rec);
      }
      return out;
    },

    async updateCounter(credentialId: Base64Url, newCounter: number): Promise<void> {
      const rec = byCredentialId.get(credentialId);
      if (!rec) return;
      byCredentialId.set(credentialId, { ...rec, counter: newCounter, lastUsedAt: Date.now() });
    },

    async updateBackupState(credentialId: Base64Url, backupState: boolean): Promise<void> {
      const rec = byCredentialId.get(credentialId);
      if (!rec) return;
      byCredentialId.set(credentialId, { ...rec, backupState });
    },

    async deleteByCredentialId(credentialId: Base64Url): Promise<void> {
      const rec = byCredentialId.get(credentialId);
      if (!rec) return;
      byCredentialId.delete(credentialId);
      const set = byUserId.get(rec.userId);
      if (set) {
        set.delete(credentialId);
        if (set.size === 0) byUserId.delete(rec.userId);
      }
    },
  };
}
