import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  signChallengeToken,
  verifyChallengeToken,
} from '../server/challenge.js';
import {
  InternalError,
  InvalidChallengeTokenError,
  WrongCeremonyError,
} from '../errors/index.js';
import {
  DEFAULT_CHALLENGE_TTL_MS,
  MAX_CHALLENGE_TTL_MS,
  MIN_CHALLENGE_TTL_MS,
} from '../server/defaults.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import { encodeUtf8 } from '../core/encoding/utf8.js';

const KEYS: ChallengeSigningKeys = {
  active: { kid: 'active-1', secret: 'active-secret-bytes' },
};

const ROTATION_KEYS: ChallengeSigningKeys = {
  active: { kid: 'k2', secret: 'new-secret' },
  previous: [{ kid: 'k1', secret: 'old-secret' }],
};

afterEach(() => {
  vi.useRealTimers();
});

describe('signChallengeToken', () => {
  it('should mint a fresh challenge and a 3-part envelope', async () => {
    const { challenge, challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
    });
    expect(challenge.length).toBe(32);
    expect(challengeToken.split('.').length).toBe(3);
  });

  it('should embed the userId binding when provided', async () => {
    const userId = encodeUtf8('user-42');
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
      userId,
    });
    const { userId: extracted } = await verifyChallengeToken(challengeToken, KEYS, 'reg', userId);
    expect(extracted).toBeDefined();
    expect(new TextDecoder().decode(extracted!)).toBe('user-42');
  });

  it('should accept a custom challengeBytes length', async () => {
    const { challenge } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'auth',
      challengeBytes: 16,
    });
    expect(challenge.length).toBe(16);
  });

  it('should accept secret as a Uint8Array', async () => {
    const keys: ChallengeSigningKeys = {
      active: { kid: 'k', secret: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]) },
    };
    const { challengeToken } = await signChallengeToken({ signingKeys: keys, ceremony: 'reg' });
    const { challenge } = await verifyChallengeToken(challengeToken, keys, 'reg');
    expect(challenge.length).toBe(32);
  });

  it('should reject ttlMs below the minimum', async () => {
    await expect(
      signChallengeToken({
        signingKeys: KEYS,
        ceremony: 'reg',
        ttlMs: MIN_CHALLENGE_TTL_MS - 1,
      }),
    ).rejects.toThrow(InternalError);
  });

  it('should reject ttlMs above the maximum', async () => {
    await expect(
      signChallengeToken({
        signingKeys: KEYS,
        ceremony: 'reg',
        ttlMs: MAX_CHALLENGE_TTL_MS + 1,
      }),
    ).rejects.toThrow(InternalError);
  });

  it('should reject when signingKeys.active is missing', async () => {
    await expect(
      signChallengeToken({
        signingKeys: { active: { kid: '', secret: '' } } as ChallengeSigningKeys,
        ceremony: 'reg',
      }),
    ).rejects.toThrow(InternalError);
  });

  it('should default to the configured TTL', async () => {
    expect(DEFAULT_CHALLENGE_TTL_MS).toBeGreaterThanOrEqual(MIN_CHALLENGE_TTL_MS);
  });
});

describe('verifyChallengeToken', () => {
  it('should verify a valid envelope and return the original challenge', async () => {
    const { challenge, challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
    });
    const { challenge: extracted } = await verifyChallengeToken(challengeToken, KEYS, 'reg');
    expect(Array.from(extracted)).toEqual(Array.from(challenge));
  });

  it('should reject a malformed envelope (not 3 parts)', async () => {
    await expect(verifyChallengeToken('not-a-token', KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
    await expect(verifyChallengeToken('a.b', KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should reject when the header / payload is not valid JSON', async () => {
    const bad = 'aGVsbG8.dGV4dA.AAAA';
    await expect(verifyChallengeToken(bad, KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should reject when the header alg / typ / kid are wrong', async () => {
    // Build an envelope with bogus alg.
    const header = btoa(JSON.stringify({ alg: 'none', typ: 'PSK1', kid: 'active-1' }))
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    const payload = btoa(
      JSON.stringify({
        ch: 'AAAA',
        c: 'reg',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
      }),
    )
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    await expect(verifyChallengeToken(`${header}.${payload}.AAAA`, KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should reject an unknown kid', async () => {
    const otherKeys: ChallengeSigningKeys = { active: { kid: 'other', secret: 'x' } };
    const { challengeToken } = await signChallengeToken({
      signingKeys: otherKeys,
      ceremony: 'reg',
    });
    await expect(verifyChallengeToken(challengeToken, KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should throw WrongCeremonyError on a ceremony binding mismatch', async () => {
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
    });
    await expect(verifyChallengeToken(challengeToken, KEYS, 'auth')).rejects.toThrow(
      WrongCeremonyError,
    );
  });

  it('should reject when the HMAC tag does not verify (tampered envelope)', async () => {
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
    });
    const tampered = challengeToken.replace(/.$/, 'A');
    await expect(verifyChallengeToken(tampered, KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should reject an expired envelope', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
      ttlMs: MIN_CHALLENGE_TTL_MS,
    });
    vi.setSystemTime(new Date('2026-01-01T00:01:00Z')); // 60 s later
    await expect(verifyChallengeToken(challengeToken, KEYS, 'reg')).rejects.toThrow(
      InvalidChallengeTokenError,
    );
  });

  it('should accept a key listed under previous (rotation)', async () => {
    const { challengeToken } = await signChallengeToken({
      signingKeys: { active: { kid: 'k1', secret: 'old-secret' } },
      ceremony: 'reg',
    });
    // Caller has now rotated to k2, with k1 still in `previous`.
    const { challenge } = await verifyChallengeToken(challengeToken, ROTATION_KEYS, 'reg');
    expect(challenge.length).toBe(32);
  });

  it('should reject a userId binding mismatch', async () => {
    const userId = encodeUtf8('user-1');
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'reg',
      userId,
    });
    await expect(
      verifyChallengeToken(challengeToken, KEYS, 'reg', encodeUtf8('user-2')),
    ).rejects.toThrow(InvalidChallengeTokenError);
  });

  it('should ignore expectedUserId when the envelope carries no uid (discoverable flow)', async () => {
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'auth',
    });
    const { userId } = await verifyChallengeToken(
      challengeToken,
      KEYS,
      'auth',
      encodeUtf8('any'),
    );
    expect(userId).toBeUndefined();
  });
});

describe('ceremony-binding ordering (security)', () => {
  it('should reject a ceremony mismatch even when the HMAC tag has been tampered', async () => {
    const { challengeToken } = await signChallengeToken({
      signingKeys: KEYS,
      ceremony: 'auth',
    });
    const tampered = challengeToken.replace(/.$/, 'X');
    // Ordering matters: the WrongCeremonyError must come BEFORE the tag check
    // so an attacker cannot probe signing-key liveness via the response shape.
    await expect(verifyChallengeToken(tampered, KEYS, 'reg')).rejects.toThrow(WrongCeremonyError);
  });
});
