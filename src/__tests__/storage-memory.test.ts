import { describe, expect, it } from 'vitest';
import { createMemoryCredentialStore } from '../storage/memory.js';
import { InvalidStateError } from '../errors/index.js';
import type { Base64Url } from '../types/webauthn.js';
import type { AaguidString } from '../types/webauthn.js';
import type { NewCredentialRecord } from '../types/credential.js';

type UserId = string;

function makeRecord(overrides: Partial<NewCredentialRecord<UserId>> = {}): NewCredentialRecord<UserId> {
  return {
    credentialId: 'cred-1' as Base64Url,
    userId: 'user-1',
    publicKey: 'pub-1' as Base64Url,
    aaguid: '00000000-0000-0000-0000-000000000000' as AaguidString,
    counter: 0,
    transports: ['internal'],
    backupEligible: true,
    backupState: false,
    deviceType: 'multiDevice',
    ...overrides,
  };
}

describe('createMemoryCredentialStore', () => {
  it('should create and retrieve a credential by id', async () => {
    const store = createMemoryCredentialStore<UserId>();
    const created = await store.create(makeRecord());
    expect(created.credentialId).toBe('cred-1');
    expect(created.lastUsedAt).toBeNull();
    expect(created.createdAt).toBeTypeOf('number');

    const found = await store.findByCredentialId('cred-1' as Base64Url);
    expect(found?.credentialId).toBe('cred-1');
  });

  it('should throw InvalidStateError when userId is missing on create', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await expect(
      store.create(makeRecord({ userId: undefined as unknown as UserId })),
    ).rejects.toThrow(InvalidStateError);
  });

  it('should throw InvalidStateError on duplicate credentialId', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await expect(store.create(makeRecord())).rejects.toThrow(InvalidStateError);
  });

  it('should return null for an unknown credentialId', async () => {
    const store = createMemoryCredentialStore<UserId>();
    expect(await store.findByCredentialId('does-not-exist' as Base64Url)).toBeNull();
  });

  it('should list credentials by userId', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await store.create(makeRecord({ credentialId: 'cred-2' as Base64Url }));
    await store.create(
      makeRecord({ credentialId: 'cred-3' as Base64Url, userId: 'user-2' }),
    );

    const list = await store.listByUserId('user-1');
    expect(list).toHaveLength(2);
    expect(list.map((c) => c.credentialId).sort()).toEqual(['cred-1', 'cred-2']);

    expect(await store.listByUserId('user-2')).toHaveLength(1);
    expect(await store.listByUserId('unknown')).toEqual([]);
  });

  it('should update the counter and bump lastUsedAt', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await store.updateCounter('cred-1' as Base64Url, 7);
    const found = await store.findByCredentialId('cred-1' as Base64Url);
    expect(found?.counter).toBe(7);
    expect(found?.lastUsedAt).toBeTypeOf('number');
  });

  it('should silently no-op updateCounter on unknown credential', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await expect(store.updateCounter('missing' as Base64Url, 1)).resolves.toBeUndefined();
  });

  it('should update the backup state independent of the counter', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await store.updateBackupState('cred-1' as Base64Url, true);
    const found = await store.findByCredentialId('cred-1' as Base64Url);
    expect(found?.backupState).toBe(true);
  });

  it('should silently no-op updateBackupState on unknown credential', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await expect(
      store.updateBackupState('missing' as Base64Url, true),
    ).resolves.toBeUndefined();
  });

  it('should delete a credential and remove the user index entry when empty', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await store.deleteByCredentialId('cred-1' as Base64Url);
    expect(await store.findByCredentialId('cred-1' as Base64Url)).toBeNull();
    expect(await store.listByUserId('user-1')).toEqual([]);
  });

  it('should retain the user index when other credentials remain', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await store.create(makeRecord());
    await store.create(makeRecord({ credentialId: 'cred-2' as Base64Url }));
    await store.deleteByCredentialId('cred-1' as Base64Url);
    const list = await store.listByUserId('user-1');
    expect(list.map((c) => c.credentialId)).toEqual(['cred-2']);
  });

  it('should silently no-op deleteByCredentialId on unknown credential', async () => {
    const store = createMemoryCredentialStore<UserId>();
    await expect(
      store.deleteByCredentialId('missing' as Base64Url),
    ).resolves.toBeUndefined();
  });
});
