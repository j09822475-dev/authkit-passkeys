import { describe, expect, it } from 'vitest';
import { verifyAuthentication } from '../server/verify-authentication.js';
import { signChallengeToken } from '../server/challenge.js';
import {
  buildAuthenticationFixture,
  generateP256Keypair,
  toBase64Url,
} from './fixtures/webauthn.js';
import { coseKeyEs256 } from './fixtures/webauthn.js';
import { createMemoryCredentialStore } from '../storage/memory.js';
import {
  AuthenticationFailedError,
  CounterRegressionError,
  InvalidChallengeError,
  InvalidOriginError,
  InvalidRpIdError,
  UserVerificationRequiredError,
} from '../errors/index.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import type {
  AaguidString,
  AuthenticationResponseJSON,
  Base64Url,
} from '../types/webauthn.js';

const KEYS: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'auth-secret' },
};

interface AuthSetupOptions {
  rpId?: string;
  origin?: string;
  uv?: boolean;
  storedCounter?: number;
  signCount?: number;
  invalidSignature?: boolean;
  storedBE?: boolean;
  authBE?: boolean;
  authBS?: boolean;
  storedBS?: boolean;
}

async function setupAuth(opts: AuthSetupOptions = {}) {
  const rpId = opts.rpId ?? 'example.com';
  const origin = opts.origin ?? 'https://example.com';
  const kp = await generateP256Keypair();
  const credentialId = new Uint8Array([10, 20, 30, 40, 50]);
  const store = createMemoryCredentialStore<string>();
  await store.create({
    credentialId: toBase64Url(credentialId) as Base64Url,
    userId: 'user-z',
    publicKey: toBase64Url(coseKeyEs256(kp.jwk)) as Base64Url,
    aaguid: '00000000-0000-0000-0000-000000000000' as AaguidString,
    counter: opts.storedCounter ?? 0,
    transports: ['internal'],
    backupEligible: opts.storedBE ?? false,
    backupState: opts.storedBS ?? false,
    deviceType: opts.storedBE ? 'multiDevice' : 'singleDevice',
  });

  const { challenge, challengeToken } = await signChallengeToken({
    signingKeys: KEYS,
    ceremony: 'auth',
  });

  const fixture = await buildAuthenticationFixture({
    rpId,
    origin,
    challenge,
    privateKey: kp.privateKey,
    credentialId,
    signCount: opts.signCount ?? 1,
    uv: opts.uv ?? true,
    ...(opts.authBE !== undefined ? { be: opts.authBE } : {}),
    ...(opts.authBS !== undefined ? { bs: opts.authBS } : {}),
    ...(opts.invalidSignature !== undefined ? { invalidSignature: opts.invalidSignature } : {}),
  });

  const response: AuthenticationResponseJSON = {
    id: toBase64Url(credentialId) as Base64Url,
    rawId: toBase64Url(credentialId) as Base64Url,
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(fixture.clientDataJSON) as Base64Url,
      authenticatorData: toBase64Url(fixture.authData) as Base64Url,
      signature: toBase64Url(fixture.signature) as Base64Url,
    },
    clientExtensionResults: {},
  };

  return { rpId, origin, store, challengeToken, response, credentialId };
}

describe('verifyAuthentication', () => {
  it('should produce a VerifiedAuthentication on a happy-path authentication', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({ signCount: 5 });
    const events: unknown[] = [];
    const r = await verifyAuthentication({
      response,
      challengeToken,
      expectedOrigin: origin,
      expectedRpId: rpId,
      store,
      signingKeys: KEYS,
      onVerified: (ev) => {
        events.push(ev);
      },
    });
    expect(r.userId).toBe('user-z');
    expect(r.newCounter).toBe(5);
    expect(r.userVerified).toBe(true);
    expect(events).toHaveLength(1);
  });

  it('should accept counter 0 → 0 (sync passkey)', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({
      signCount: 0,
      storedCounter: 0,
    });
    const r = await verifyAuthentication({
      response,
      challengeToken,
      expectedOrigin: origin,
      expectedRpId: rpId,
      store,
      signingKeys: KEYS,
    });
    expect(r.newCounter).toBe(0);
  });

  it('should throw CounterRegressionError on a strict-less counter', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({
      signCount: 1,
      storedCounter: 5,
    });
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(CounterRegressionError);
  });

  it('should reject InvalidRpIdError on an RP-ID hash mismatch', async () => {
    const { origin, store, challengeToken, response } = await setupAuth();
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: 'other.com',
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidRpIdError);
  });

  it('should reject InvalidChallengeError when the clientData challenge differs from the token', async () => {
    const { rpId, origin, store, response } = await setupAuth();
    // Brand new token with a fresh challenge that does not match the response.
    const { challengeToken: bad } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'auth',
    });
    await expect(
      verifyAuthentication({
        response,
        challengeToken: bad,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidChallengeError);
  });

  it('should reject InvalidOriginError when expectedOrigin does not match', async () => {
    const { rpId, store, challengeToken, response } = await setupAuth();
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: 'https://other.com',
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidOriginError);
  });

  it('should collapse a malformed signature into AuthenticationFailedError', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth();
    const broken: AuthenticationResponseJSON = {
      ...response,
      response: { ...response.response, signature: '!@#$%not-base64' as Base64Url },
    };
    await expect(
      verifyAuthentication({
        response: broken,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should collapse an unknown credential into AuthenticationFailedError (no enumeration leak)', async () => {
    const { rpId, origin, challengeToken, response } = await setupAuth();
    const emptyStore = createMemoryCredentialStore<string>();
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store: emptyStore,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should collapse a base64url-malformed credential id into AuthenticationFailedError', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth();
    const broken: AuthenticationResponseJSON = { ...response, id: '!!!' as Base64Url };
    await expect(
      verifyAuthentication({
        response: broken,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should collapse an invalid signature into AuthenticationFailedError', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({
      invalidSignature: true,
    });
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should reject UserVerificationRequiredError when uv flag is 0 by default', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({ uv: false });
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(UserVerificationRequiredError);
  });

  it('should accept uv:false when requireUserVerification is false', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({ uv: false });
    const r = await verifyAuthentication({
      response,
      challengeToken,
      expectedOrigin: origin,
      expectedRpId: rpId,
      store,
      signingKeys: KEYS,
      requireUserVerification: false,
    });
    expect(r.userVerified).toBe(false);
  });

  it('should reject AuthenticationFailedError when BE bit regresses 1 → 0', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({
      storedBE: true,
      authBE: false,
    });
    await expect(
      verifyAuthentication({
        response,
        challengeToken,
        expectedOrigin: origin,
        expectedRpId: rpId,
        store,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(AuthenticationFailedError);
  });

  it('should signal newlyBackedUp via the onVerified hook on BS 0 → 1 transition', async () => {
    const { rpId, origin, store, challengeToken, response } = await setupAuth({
      storedBE: true,
      storedBS: false,
      authBE: true,
      authBS: true,
    });
    let captured: { newlyBackedUp?: boolean } | undefined;
    await verifyAuthentication({
      response,
      challengeToken,
      expectedOrigin: origin,
      expectedRpId: rpId,
      store,
      signingKeys: KEYS,
      onVerified: (ev) => {
        captured = ev as { newlyBackedUp?: boolean };
      },
    });
    expect(captured?.newlyBackedUp).toBe(true);
  });
});
