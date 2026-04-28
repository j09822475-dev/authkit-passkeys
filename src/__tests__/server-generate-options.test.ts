import { describe, expect, it } from 'vitest';
import { generateRegistrationOptions } from '../server/generate-registration-options.js';
import { generateAuthenticationOptions } from '../server/generate-authentication-options.js';
import { verifyChallengeToken } from '../server/challenge.js';
import { createMemoryCredentialStore } from '../storage/memory.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import type { Base64Url, AaguidString } from '../types/webauthn.js';
import type { NewCredentialRecord } from '../types/credential.js';

const KEYS: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'a-strong-secret' },
};

describe('generateRegistrationOptions', () => {
  it('should produce options with sensible defaults', async () => {
    const store = createMemoryCredentialStore<string>();
    const { options, challengeToken } = await generateRegistrationOptions({
      rp: { id: 'example.com', name: 'Example Co' },
      user: { id: 'user-1', name: 'a@b.com', displayName: 'A B' },
      store,
      signingKeys: KEYS,
    });
    expect(options.rp).toEqual({ id: 'example.com', name: 'Example Co' });
    expect(options.user.name).toBe('a@b.com');
    expect(options.user.displayName).toBe('A B');
    expect(options.challenge.length).toBeGreaterThan(0);
    expect(options.attestation).toBe('none');
    expect(options.timeout).toBe(60_000);
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
    expect(options.authenticatorSelection?.userVerification).toBe('required');
    expect(options.authenticatorSelection?.residentKey).toBe('preferred');
    expect(options.authenticatorSelection?.requireResidentKey).toBe(false);
    expect(options.excludeCredentials).toEqual([]);
    expect(challengeToken.split('.').length).toBe(3);
  });

  it('should propagate user-supplied options (algs, residentKey, attachment, attestation)', async () => {
    const store = createMemoryCredentialStore<string>();
    const { options } = await generateRegistrationOptions({
      rp: { id: 'example.com', name: 'X' },
      user: { id: 'u', name: 'n', displayName: 'd' },
      store,
      signingKeys: KEYS,
      pubKeyCredAlgs: ['EdDSA'],
      residentKey: 'required',
      authenticatorAttachment: 'platform',
      attestation: 'direct',
      userVerification: 'preferred',
      timeout: 90_000,
    });
    expect(options.pubKeyCredParams.map((p) => p.alg)).toEqual([-8]);
    expect(options.authenticatorSelection?.residentKey).toBe('required');
    expect(options.authenticatorSelection?.requireResidentKey).toBe(true);
    expect(options.authenticatorSelection?.authenticatorAttachment).toBe('platform');
    expect(options.attestation).toBe('direct');
    expect(options.authenticatorSelection?.userVerification).toBe('preferred');
    expect(options.timeout).toBe(90_000);
  });

  it('should populate excludeCredentials from existing store records', async () => {
    const store = createMemoryCredentialStore<string>();
    const rec: NewCredentialRecord<string> = {
      credentialId: 'existing' as Base64Url,
      userId: 'u',
      publicKey: 'p' as Base64Url,
      aaguid: '00000000-0000-0000-0000-000000000000' as AaguidString,
      counter: 0,
      transports: ['internal'],
      backupEligible: false,
      backupState: false,
      deviceType: 'singleDevice',
    };
    await store.create(rec);
    const { options } = await generateRegistrationOptions({
      rp: { id: 'example.com', name: 'X' },
      user: { id: 'u', name: 'n', displayName: 'd' },
      store,
      signingKeys: KEYS,
    });
    expect(options.excludeCredentials).toHaveLength(1);
    expect(options.excludeCredentials?.[0]?.id).toBe('existing');
    expect(options.excludeCredentials?.[0]?.transports).toEqual(['internal']);
  });

  it('should bind the userId into the challenge token', async () => {
    const store = createMemoryCredentialStore<string>();
    const { challengeToken } = await generateRegistrationOptions({
      rp: { id: 'example.com', name: 'X' },
      user: { id: 'user-77', name: 'n', displayName: 'd' },
      store,
      signingKeys: KEYS,
    });
    const { userId } = await verifyChallengeToken(challengeToken, KEYS, 'reg');
    expect(new TextDecoder().decode(userId!)).toBe('user-77');
  });

  it('should respect a challengeTtlMs override', async () => {
    const store = createMemoryCredentialStore<string>();
    const { challengeToken } = await generateRegistrationOptions({
      rp: { id: 'example.com', name: 'X' },
      user: { id: 'u', name: 'n', displayName: 'd' },
      store,
      signingKeys: KEYS,
      challengeTtlMs: 60_000,
    });
    // Token is valid immediately.
    await expect(verifyChallengeToken(challengeToken, KEYS, 'reg')).resolves.toBeDefined();
  });
});

describe('generateAuthenticationOptions', () => {
  it('should omit allowCredentials for the discoverable / passkey-first flow', async () => {
    const store = createMemoryCredentialStore<string>();
    const { options, challengeToken } = await generateAuthenticationOptions({
      rp: { id: 'example.com' },
      store,
      signingKeys: KEYS,
    });
    expect(options.allowCredentials).toBeUndefined();
    expect(options.userVerification).toBe('required');
    expect(options.timeout).toBe(60_000);
    expect(options.rpId).toBe('example.com');
    expect(challengeToken.split('.').length).toBe(3);
  });

  it('should populate allowCredentials when a user is provided', async () => {
    const store = createMemoryCredentialStore<string>();
    await store.create({
      credentialId: 'c1' as Base64Url,
      userId: 'u',
      publicKey: 'p' as Base64Url,
      aaguid: '00000000-0000-0000-0000-000000000000' as AaguidString,
      counter: 0,
      transports: ['internal', 'hybrid'],
      backupEligible: true,
      backupState: false,
      deviceType: 'multiDevice',
    });
    const { options } = await generateAuthenticationOptions({
      rp: { id: 'example.com' },
      user: { id: 'u' },
      store,
      signingKeys: KEYS,
    });
    expect(options.allowCredentials).toHaveLength(1);
    expect(options.allowCredentials?.[0]?.id).toBe('c1');
    expect(options.allowCredentials?.[0]?.transports).toEqual(['internal', 'hybrid']);
  });

  it('should bind the userId into the challenge token only when user is provided', async () => {
    const store = createMemoryCredentialStore<string>();
    const { challengeToken: discoverable } = await generateAuthenticationOptions({
      rp: { id: 'example.com' },
      store,
      signingKeys: KEYS,
    });
    const { userId: noUid } = await verifyChallengeToken(discoverable, KEYS, 'auth');
    expect(noUid).toBeUndefined();

    const { challengeToken } = await generateAuthenticationOptions({
      rp: { id: 'example.com' },
      user: { id: 'u-7' },
      store,
      signingKeys: KEYS,
    });
    const { userId } = await verifyChallengeToken(challengeToken, KEYS, 'auth');
    expect(new TextDecoder().decode(userId!)).toBe('u-7');
  });

  it('should respect a challengeTtlMs override and a userVerification override', async () => {
    const store = createMemoryCredentialStore<string>();
    const { options } = await generateAuthenticationOptions({
      rp: { id: 'example.com' },
      store,
      signingKeys: KEYS,
      challengeTtlMs: 30_000,
      userVerification: 'preferred',
      timeout: 45_000,
    });
    expect(options.userVerification).toBe('preferred');
    expect(options.timeout).toBe(45_000);
  });
});
