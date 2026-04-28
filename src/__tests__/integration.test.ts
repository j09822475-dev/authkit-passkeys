/**
 * End-to-end integration tests — the server emits options, the browser
 * fixtures sign with a real ECDSA keypair, and the verifyRegistration /
 * verifyAuthentication path round-trips back through the public API.
 */

import { describe, expect, it } from 'vitest';
import { generateRegistrationOptions } from '../server/generate-registration-options.js';
import { generateAuthenticationOptions } from '../server/generate-authentication-options.js';
import { verifyRegistration } from '../server/verify-registration.js';
import { verifyAuthentication } from '../server/verify-authentication.js';
import { createMemoryCredentialStore } from '../storage/memory.js';
import { fromBase64Url, toBase64Url } from '../core/encoding/base64url.js';
import {
  buildAuthenticationFixture,
  buildRegistrationFixture,
  generateP256Keypair,
} from './fixtures/webauthn.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import type {
  AaguidString,
  AuthenticationResponseJSON,
  Base64Url,
  RegistrationResponseJSON,
} from '../types/webauthn.js';
import type { CredentialRecord } from '../types/credential.js';
import {
  AuthenticationFailedError,
  CounterRegressionError,
} from '../errors/index.js';

const KEYS: ChallengeSigningKeys = {
  active: { kid: 'integration-1', secret: 'integration-test-secret' },
};

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';
const USER_ID = 'integration-user';

describe('register → authenticate happy path', () => {
  it('should round-trip a full registration and a subsequent authentication', async () => {
    const store = createMemoryCredentialStore<string>();

    // Step 1: server emits registration options.
    const reg = await generateRegistrationOptions({
      rp: { id: RP_ID, name: 'Example' },
      user: { id: USER_ID, name: 'a@example.com', displayName: 'A' },
      store,
      signingKeys: KEYS,
    });
    expect(reg.options.excludeCredentials).toEqual([]);

    // Step 2: browser-side fixture signs using the issued challenge.
    const issuedChallenge = fromBase64Url(reg.options.challenge);
    const kp = await generateP256Keypair();
    const regFixture = await buildRegistrationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge: issuedChallenge,
      keypair: kp,
    });

    const regResponse: RegistrationResponseJSON = {
      id: toBase64Url(regFixture.credentialId) as Base64Url,
      rawId: toBase64Url(regFixture.credentialId) as Base64Url,
      type: 'public-key',
      response: {
        clientDataJSON: toBase64Url(regFixture.clientDataJSON) as Base64Url,
        attestationObject: toBase64Url(regFixture.attestationObject) as Base64Url,
        transports: ['internal'],
      },
      clientExtensionResults: {},
    };

    // Step 3: server verifies and returns NewCredentialRecord.
    const newRecord = await verifyRegistration({
      response: regResponse,
      challengeToken: reg.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      signingKeys: KEYS,
    });
    expect(newRecord.userId).toBe(USER_ID);

    // Step 4: caller persists.
    await store.create(newRecord);
    const stored = await store.findByCredentialId(newRecord.credentialId);
    expect(stored).toBeDefined();

    // Step 5: server emits authentication options. excludeCredentials → allowCredentials.
    const auth = await generateAuthenticationOptions({
      rp: { id: RP_ID },
      user: { id: USER_ID },
      store,
      signingKeys: KEYS,
    });
    expect(auth.options.allowCredentials).toHaveLength(1);

    // Step 6: browser signs the authentication challenge.
    const authChallenge = fromBase64Url(auth.options.challenge);
    const authFixture = await buildAuthenticationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge: authChallenge,
      privateKey: kp.privateKey,
      credentialId: regFixture.credentialId,
      signCount: 7,
      uv: true,
    });
    const authResponse: AuthenticationResponseJSON = {
      id: toBase64Url(regFixture.credentialId) as Base64Url,
      rawId: toBase64Url(regFixture.credentialId) as Base64Url,
      type: 'public-key',
      response: {
        clientDataJSON: toBase64Url(authFixture.clientDataJSON) as Base64Url,
        authenticatorData: toBase64Url(authFixture.authData) as Base64Url,
        signature: toBase64Url(authFixture.signature) as Base64Url,
      },
      clientExtensionResults: {},
    };

    const result = await verifyAuthentication({
      response: authResponse,
      challengeToken: auth.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      store,
      signingKeys: KEYS,
    });

    expect(result.userId).toBe(USER_ID);
    expect(result.newCounter).toBe(7);
    expect(result.userVerified).toBe(true);

    // Step 7: caller persists the new counter.
    await store.updateCounter(result.credential.credentialId, result.newCounter);
    const after = (await store.findByCredentialId(
      result.credential.credentialId,
    )) as CredentialRecord<string>;
    expect(after.counter).toBe(7);
  });
});

describe('register → authenticate failure modes', () => {
  it('should reject AuthenticationFailedError when the wrong key signs the assertion', async () => {
    const store = createMemoryCredentialStore<string>();

    const reg = await generateRegistrationOptions({
      rp: { id: RP_ID, name: 'X' },
      user: { id: USER_ID, name: 'n', displayName: 'd' },
      store,
      signingKeys: KEYS,
    });
    const challenge = fromBase64Url(reg.options.challenge);
    const kp = await generateP256Keypair();
    const regFixture = await buildRegistrationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge,
      keypair: kp,
    });

    const newRecord = await verifyRegistration({
      response: {
        id: toBase64Url(regFixture.credentialId) as Base64Url,
        rawId: toBase64Url(regFixture.credentialId) as Base64Url,
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(regFixture.clientDataJSON) as Base64Url,
          attestationObject: toBase64Url(regFixture.attestationObject) as Base64Url,
        },
        clientExtensionResults: {},
      },
      challengeToken: reg.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      signingKeys: KEYS,
    });
    await store.create(newRecord);

    const auth = await generateAuthenticationOptions({
      rp: { id: RP_ID },
      user: { id: USER_ID },
      store,
      signingKeys: KEYS,
    });
    // Sign with a different keypair while reusing the registered credentialId.
    const wrong = await generateP256Keypair();
    const fixture = await buildAuthenticationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge: fromBase64Url(auth.options.challenge),
      privateKey: wrong.privateKey,
      credentialId: regFixture.credentialId,
      uv: true,
    });
    await expect(
      verifyAuthentication({
        response: {
          id: toBase64Url(regFixture.credentialId) as Base64Url,
          rawId: toBase64Url(regFixture.credentialId) as Base64Url,
          type: 'public-key',
          response: {
            clientDataJSON: toBase64Url(fixture.clientDataJSON) as Base64Url,
            authenticatorData: toBase64Url(fixture.authData) as Base64Url,
            signature: toBase64Url(fixture.signature) as Base64Url,
          },
          clientExtensionResults: {},
        },
        challengeToken: auth.challengeToken,
        expectedOrigin: ORIGIN,
        expectedRpId: RP_ID,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should detect counter regression on a replayed assertion', async () => {
    const store = createMemoryCredentialStore<string>();
    const kp = await generateP256Keypair();
    // Pre-populate the store with a stored counter of 100.
    const credentialId = new Uint8Array([1, 2, 3, 4, 5]);
    const reg = await buildRegistrationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      keypair: kp,
      credentialId,
    });
    await store.create({
      credentialId: toBase64Url(reg.credentialId) as Base64Url,
      userId: USER_ID,
      publicKey: toBase64Url(reg.credentialPublicKey) as Base64Url,
      aaguid: '00000000-0000-0000-0000-000000000000' as AaguidString,
      counter: 100,
      transports: ['internal'],
      backupEligible: false,
      backupState: false,
      deviceType: 'singleDevice',
    });

    const auth = await generateAuthenticationOptions({
      rp: { id: RP_ID },
      user: { id: USER_ID },
      store,
      signingKeys: KEYS,
    });
    const fixture = await buildAuthenticationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge: fromBase64Url(auth.options.challenge),
      privateKey: kp.privateKey,
      credentialId: reg.credentialId,
      signCount: 1, // Lower than stored 100 → regression.
      uv: true,
    });
    await expect(
      verifyAuthentication({
        response: {
          id: toBase64Url(reg.credentialId) as Base64Url,
          rawId: toBase64Url(reg.credentialId) as Base64Url,
          type: 'public-key',
          response: {
            clientDataJSON: toBase64Url(fixture.clientDataJSON) as Base64Url,
            authenticatorData: toBase64Url(fixture.authData) as Base64Url,
            signature: toBase64Url(fixture.signature) as Base64Url,
          },
          clientExtensionResults: {},
        },
        challengeToken: auth.challengeToken,
        expectedOrigin: ORIGIN,
        expectedRpId: RP_ID,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(CounterRegressionError);
  });
});

describe('challenge token rotation', () => {
  it('should accept a token signed under a previous-key during rotation', async () => {
    const store = createMemoryCredentialStore<string>();
    const oldKeys: ChallengeSigningKeys = { active: { kid: 'old', secret: 'old-secret' } };
    const reg = await generateRegistrationOptions({
      rp: { id: RP_ID, name: 'X' },
      user: { id: USER_ID, name: 'n', displayName: 'd' },
      store,
      signingKeys: oldKeys,
    });

    // After deploy the active key is "new", but "old" is still in `previous`.
    const rotated: ChallengeSigningKeys = {
      active: { kid: 'new', secret: 'new-secret' },
      previous: [{ kid: 'old', secret: 'old-secret' }],
    };

    const challenge = fromBase64Url(reg.options.challenge);
    const kp = await generateP256Keypair();
    const fixture = await buildRegistrationFixture({
      rpId: RP_ID,
      origin: ORIGIN,
      challenge,
      keypair: kp,
    });

    const record = await verifyRegistration({
      response: {
        id: toBase64Url(fixture.credentialId) as Base64Url,
        rawId: toBase64Url(fixture.credentialId) as Base64Url,
        type: 'public-key',
        response: {
          clientDataJSON: toBase64Url(fixture.clientDataJSON) as Base64Url,
          attestationObject: toBase64Url(fixture.attestationObject) as Base64Url,
        },
        clientExtensionResults: {},
      },
      challengeToken: reg.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      signingKeys: rotated,
    });
    expect(record.userId).toBe(USER_ID);
  });
});
