import { describe, expect, it } from 'vitest';
import { verifyRegistration } from '../server/verify-registration.js';
import { signChallengeToken } from '../server/challenge.js';
import {
  buildRegistrationFixture,
  toBase64Url,
  utf8,
} from './fixtures/webauthn.js';
import {
  AaguidNotAllowedError,
  AuthenticationFailedError,
  InvalidAttestationError,
  InvalidChallengeError,
  InvalidOriginError,
  InvalidRpIdError,
  UserVerificationRequiredError,
  UnsupportedAttestationFormatError,
} from '../errors/index.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import type { RegistrationResponseJSON, AaguidString } from '../types/webauthn.js';
import type { Base64Url } from '../types/webauthn.js';

const KEYS: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'a-strong-test-secret' },
};

interface FixtureOptions {
  rpId?: string;
  origin?: string;
  uv?: boolean;
  fmt?: 'none' | 'packed';
  malformedPacked?: boolean;
  aaguid?: Uint8Array;
  challengeOverride?: Uint8Array;
}

async function setup(opts: FixtureOptions = {}) {
  const baseOpts = {
    ...(opts.rpId !== undefined ? { rpId: opts.rpId } : {}),
    ...(opts.origin !== undefined ? { origin: opts.origin } : {}),
    ...(opts.uv !== undefined ? { uv: opts.uv } : {}),
    ...(opts.fmt !== undefined ? { fmt: opts.fmt } : {}),
    ...(opts.malformedPacked !== undefined ? { malformedPacked: opts.malformedPacked } : {}),
    ...(opts.aaguid !== undefined ? { aaguid: opts.aaguid } : {}),
  };
  const { challenge: tokenChallenge, challengeToken } = await signChallengeToken({
    signingKeys: KEYS,
    ceremony: 'reg',
    userId: utf8('user-x'),
  });
  const matched = await buildRegistrationFixture({
    ...baseOpts,
    challenge: opts.challengeOverride ?? tokenChallenge,
  });
  const response: RegistrationResponseJSON = {
    id: toBase64Url(matched.credentialId) as Base64Url,
    rawId: toBase64Url(matched.credentialId) as Base64Url,
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(matched.clientDataJSON) as Base64Url,
      attestationObject: toBase64Url(matched.attestationObject) as Base64Url,
      transports: ['internal'],
    },
    clientExtensionResults: {},
  };
  return { matched, challengeToken, response };
}

describe('verifyRegistration', () => {
  it('should produce a NewCredentialRecord on a happy-path none-fmt registration', async () => {
    const { matched, challengeToken, response } = await setup();
    const events: unknown[] = [];
    const record = await verifyRegistration({
      response,
      challengeToken,
      expectedOrigin: matched.origin,
      expectedRpId: matched.rpId,
      signingKeys: KEYS,
      onVerified: (ev) => {
        events.push(ev);
      },
    });
    expect(record.credentialId).toBe(toBase64Url(matched.credentialId));
    expect(record.userId).toBe('user-x');
    expect(record.counter).toBe(0);
    expect(record.transports).toEqual(['internal']);
    expect(record.deviceType).toBe('singleDevice');
    expect(events).toHaveLength(1);
  });

  it('should accept packed self-attestation', async () => {
    const { matched, challengeToken, response } = await setup({ fmt: 'packed' });
    const record = await verifyRegistration({
      response,
      challengeToken,
      expectedOrigin: matched.origin,
      expectedRpId: matched.rpId,
      signingKeys: KEYS,
    });
    expect(record.credentialId).toBeDefined();
  });

  it('should reject when packed attestation is malformed', async () => {
    const { matched, challengeToken, response } = await setup({
      fmt: 'packed',
      malformedPacked: true,
    });
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidAttestationError);
  });

  it('should reject when expectedRpId does not match the authenticator rpIdHash', async () => {
    const { matched, challengeToken, response } = await setup();
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: 'other.com',
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidRpIdError);
  });

  it('should reject when expectedOrigin does not match', async () => {
    const { matched, challengeToken, response } = await setup();
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: 'https://evil.com',
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidOriginError);
  });

  it('should reject when the clientData challenge does not match the token-bound challenge', async () => {
    const otherChallenge = new Uint8Array(32).fill(9);
    const { matched, challengeToken, response } = await setup({
      challengeOverride: otherChallenge,
    });
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(InvalidChallengeError);
  });

  it('should reject when requireUserVerification but uv flag is 0', async () => {
    const { matched, challengeToken, response } = await setup({ uv: false });
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(UserVerificationRequiredError);
  });

  it('should accept uv:false when requireUserVerification is false', async () => {
    const { matched, challengeToken, response } = await setup({ uv: false });
    const record = await verifyRegistration({
      response,
      challengeToken,
      expectedOrigin: matched.origin,
      expectedRpId: matched.rpId,
      signingKeys: KEYS,
      requireUserVerification: false,
    });
    expect(record.credentialId).toBeDefined();
  });

  it('should reject when AAGUID is on the deny-list', async () => {
    const aaguid = new Uint8Array(16);
    aaguid[15] = 0x07;
    const { matched, challengeToken, response } = await setup({ aaguid });
    const aaguidUuid = '00000000-0000-0000-0000-000000000007' as AaguidString;
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
        policy: { deny: [aaguidUuid] },
      }),
    ).rejects.toThrow(AaguidNotAllowedError);
  });

  it('should reject an unknown attestation format', async () => {
    // Build a none-fmt registration first, then point its parsed object at "weird".
    const base = await setup();
    const tampered: RegistrationResponseJSON = base.response;
    // Re-encode the attestation object with fmt=weird-format.
    const { encodeCbor } = await import('./fixtures/cbor-encode.js');
    const { fromBase64Url } = await import('../core/encoding/base64url.js');
    const { decodeCbor } = await import('../core/cose/cbor.js');
    const original = decodeCbor(fromBase64Url(tampered.response.attestationObject)).value as Map<
      unknown,
      unknown
    >;
    const m = new Map<unknown, unknown>(original);
    m.set('fmt', 'weird-format');
    const newAtt = encodeCbor(m as never);
    tampered.response = {
      ...tampered.response,
      attestationObject: toBase64Url(newAtt) as Base64Url,
    };
    await expect(
      verifyRegistration({
        response: tampered,
        challengeToken: base.challengeToken,
        expectedOrigin: base.matched.origin,
        expectedRpId: base.matched.rpId,
        signingKeys: KEYS,
      }),
    ).rejects.toThrow(UnsupportedAttestationFormatError);
  });

  it('should fire onVerified with the audit-event payload', async () => {
    const { matched, challengeToken, response } = await setup();
    let captured: unknown;
    await verifyRegistration({
      response,
      challengeToken,
      expectedOrigin: matched.origin,
      expectedRpId: matched.rpId,
      signingKeys: KEYS,
      onVerified: (ev) => {
        captured = ev;
      },
    });
    expect(captured).toMatchObject({
      attestationFormat: 'none',
      backupEligible: false,
      deviceType: 'singleDevice',
    });
  });

  it('should not throw AuthenticationFailedError on a happy path (sanity)', async () => {
    const { matched, challengeToken, response } = await setup();
    await expect(
      verifyRegistration({
        response,
        challengeToken,
        expectedOrigin: matched.origin,
        expectedRpId: matched.rpId,
        signingKeys: KEYS,
      }),
    ).resolves.not.toThrow();
    void AuthenticationFailedError; // referenced for completeness
  });
});
