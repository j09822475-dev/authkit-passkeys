import {
  InternalError,
  InvalidChallengeTokenError,
  WrongCeremonyError,
} from '../errors/classes.js';
import { fromBase64Url, toBase64Url } from '../core/encoding/base64url.js';
import { decodeUtf8, encodeUtf8 } from '../core/encoding/utf8.js';
import { randomBytes } from '../core/crypto/random.js';
import { timingSafeEqualBytes } from '../core/crypto/bytes.js';
import { subtle } from '#webcrypto-shim';
import type { Base64Url, ChallengeToken } from '../types/webauthn.js';
import type { ChallengeSigningKeys } from '../types/options.js';
import {
  DEFAULT_CHALLENGE_BYTES,
  DEFAULT_CHALLENGE_TTL_MS,
  MAX_CHALLENGE_TTL_MS,
  MIN_CHALLENGE_TTL_MS,
} from './defaults.js';

/** Discriminator for the ceremony bound to a challenge envelope. */
export type CeremonyKind = 'reg' | 'auth';

/** Decoded envelope payload, only used internally. */
interface EnvelopePayload {
  /** Challenge bytes, base64url. */
  ch: Base64Url;
  /** Ceremony binding — `'reg'` or `'auth'`. */
  c: CeremonyKind;
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds. */
  exp: number;
  /** Optional user binding, base64url. */
  uid?: Base64Url;
}

interface EnvelopeHeader {
  alg: 'HS256';
  typ: 'PSK1';
  kid: string;
}

interface NormalizedKey {
  kid: string;
  bytes: Uint8Array;
}

/**
 * Mint a fresh challenge AND a signed envelope binding it to a ceremony, the
 * active signing key (`kid`), and an optional `userId`. The server stays
 * stateless — callers only have to round-trip the returned token.
 *
 * @param input.signingKeys  Caller-supplied signing keys (active + previous).
 * @param input.ceremony     `'reg'` or `'auth'` — bound into the envelope so a
 *                           registration token cannot be replayed at the auth
 *                           endpoint and vice-versa.
 * @param input.userId       Optional binding — set for registration always,
 *                           set for authentication only on non-discoverable flows.
 * @param input.ttlMs        Token lifetime in ms. Default 5 min, min 30 s, max 10 min.
 * @param input.challengeBytes  Challenge length (default 32).
 * @returns                  `{ challenge, challengeToken }` — `challenge` is the
 *                           raw bytes, `challengeToken` is the signed envelope
 *                           the verifier will consume.
 * @throws {InternalError}   When `ttlMs` is out of range or signing keys are missing.
 *
 * @example
 *   const { challenge, challengeToken } = await signChallengeToken({
 *     signingKeys: PASSKEY_SIGNING_KEYS,
 *     ceremony: 'reg',
 *     userId: encodeUtf8(user.id),
 *   });
 */
export async function signChallengeToken(input: {
  signingKeys: ChallengeSigningKeys;
  ceremony: CeremonyKind;
  userId?: Uint8Array;
  ttlMs?: number;
  challengeBytes?: number;
}): Promise<{ challenge: Uint8Array; challengeToken: ChallengeToken }> {
  const ttlMs = input.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  if (ttlMs < MIN_CHALLENGE_TTL_MS || ttlMs > MAX_CHALLENGE_TTL_MS) {
    throw new InternalError(
      `challenge ttlMs ${ttlMs} out of range [${MIN_CHALLENGE_TTL_MS}, ${MAX_CHALLENGE_TTL_MS}].`,
    );
  }
  const active = normalizeActiveKey(input.signingKeys);

  const challenge = randomBytes(input.challengeBytes ?? DEFAULT_CHALLENGE_BYTES);
  const nowSec = Math.floor(Date.now() / 1000);
  const ttlSec = Math.floor(ttlMs / 1000);

  const header: EnvelopeHeader = { alg: 'HS256', typ: 'PSK1', kid: active.kid };
  const payload: EnvelopePayload = {
    ch: toBase64Url(challenge),
    c: input.ceremony,
    iat: nowSec,
    exp: nowSec + ttlSec,
    ...(input.userId ? { uid: toBase64Url(input.userId) } : {}),
  };

  const head = toBase64Url(encodeUtf8(JSON.stringify(header)));
  const body = toBase64Url(encodeUtf8(JSON.stringify(payload)));
  const signing = `${head}.${body}`;
  const sig = await hmac(active.bytes, encodeUtf8(signing));
  const token = `${signing}.${toBase64Url(sig)}` as ChallengeToken;
  return { challenge, challengeToken: token };
}

/**
 * Verify a challenge envelope: HMAC tag (constant-time via `crypto.subtle.verify`),
 * expiry, ceremony binding, and optional user binding.
 *
 * @param token        The token returned by {@link signChallengeToken}.
 * @param signingKeys  The same signing keys the issuer used (active + previous).
 * @param ceremony     The ceremony this verifier expects (`'reg'` or `'auth'`).
 * @param expectedUserId  Optional — when set, the envelope's `uid` must match.
 * @returns            `{ challenge, userId? }` extracted from the verified envelope.
 * @throws {InvalidChallengeTokenError}  Tag mismatch, expired, malformed.
 * @throws {WrongCeremonyError}          Ceremony binding does not match.
 *
 * @example
 *   const { challenge } = await verifyChallengeToken(token, signingKeys, 'reg');
 */
export async function verifyChallengeToken(
  token: ChallengeToken | string,
  signingKeys: ChallengeSigningKeys,
  ceremony: CeremonyKind,
  expectedUserId?: Uint8Array,
): Promise<{ challenge: Uint8Array; userId: Uint8Array | undefined }> {
  const parts = String(token).split('.');
  if (parts.length !== 3) {
    throw new InvalidChallengeTokenError(undefined, {
      details: { reason: 'challenge_malformed' },
    });
  }
  const [headEnc, bodyEnc, sigEnc] = parts as [string, string, string];

  let header: EnvelopeHeader;
  let payload: EnvelopePayload;
  try {
    header = JSON.parse(decodeUtf8(fromBase64Url(headEnc))) as EnvelopeHeader;
    payload = JSON.parse(decodeUtf8(fromBase64Url(bodyEnc))) as EnvelopePayload;
  } catch (cause) {
    throw new InvalidChallengeTokenError(undefined, {
      cause,
      details: { reason: 'challenge_malformed' },
    });
  }

  if (header.alg !== 'HS256' || header.typ !== 'PSK1' || typeof header.kid !== 'string') {
    throw new InvalidChallengeTokenError('Invalid envelope header.', {
      details: { reason: 'challenge_malformed' },
    });
  }

  const key = findKey(signingKeys, header.kid);
  if (!key) {
    throw new InvalidChallengeTokenError('Unknown signing-key kid.', {
      details: { reason: 'challenge_malformed' },
    });
  }

  // Ceremony binding — enforced BEFORE tag verify so a valid-HMAC envelope
  // captured from one ceremony cannot be replayed at the other to probe
  // signing-key liveness. The error is deterministic for any envelope (valid
  // or forged HMAC) carrying the wrong ceremony, which means it leaks no
  // information about the signing key.
  if (payload.c !== ceremony) {
    throw new WrongCeremonyError(
      `Token ceremony "${payload.c}" does not match expected "${ceremony}".`,
      { details: { reason: 'challenge_malformed' } },
    );
  }

  let sig: Uint8Array;
  try {
    sig = fromBase64Url(sigEnc);
  } catch (cause) {
    throw new InvalidChallengeTokenError(undefined, {
      cause,
      details: { reason: 'challenge_malformed' },
    });
  }

  const tagOk = await hmacVerify(key.bytes, sig, encodeUtf8(`${headEnc}.${bodyEnc}`));
  if (!tagOk) {
    throw new InvalidChallengeTokenError('Challenge envelope tag mismatch.', {
      details: { reason: 'challenge_malformed' },
    });
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < nowSec) {
    throw new InvalidChallengeTokenError('Challenge envelope expired.', {
      details: { reason: 'challenge_expired' },
    });
  }

  let challenge: Uint8Array;
  try {
    challenge = fromBase64Url(payload.ch);
  } catch (cause) {
    throw new InvalidChallengeTokenError(undefined, {
      cause,
      details: { reason: 'challenge_malformed' },
    });
  }

  let userId: Uint8Array | undefined;
  if (payload.uid) {
    try {
      userId = fromBase64Url(payload.uid);
    } catch (cause) {
      throw new InvalidChallengeTokenError(undefined, {
        cause,
        details: { reason: 'challenge_malformed' },
      });
    }
  }

  if (expectedUserId && userId && !timingSafeEqualBytes(userId, expectedUserId)) {
    throw new InvalidChallengeTokenError('Token userId binding mismatch.', {
      details: { reason: 'challenge_malformed' },
    });
  }

  return { challenge, userId };
}

function normalizeActiveKey(keys: ChallengeSigningKeys): NormalizedKey {
  if (!keys || !keys.active || !keys.active.kid || !keys.active.secret) {
    throw new InternalError('signingKeys.active is required.');
  }
  return {
    kid: keys.active.kid,
    bytes: typeof keys.active.secret === 'string' ? encodeUtf8(keys.active.secret) : keys.active.secret,
  };
}

function findKey(keys: ChallengeSigningKeys, kid: string): NormalizedKey | undefined {
  if (keys.active && keys.active.kid === kid) {
    return {
      kid: keys.active.kid,
      bytes:
        typeof keys.active.secret === 'string' ? encodeUtf8(keys.active.secret) : keys.active.secret,
    };
  }
  if (keys.previous) {
    for (const k of keys.previous) {
      if (k.kid === kid) {
        return {
          kid: k.kid,
          bytes: typeof k.secret === 'string' ? encodeUtf8(k.secret) : k.secret,
        };
      }
    }
  }
  return undefined;
}

async function hmac(secret: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await subtle.sign('HMAC', key, data));
}

async function hmacVerify(secret: Uint8Array, sig: Uint8Array, data: Uint8Array): Promise<boolean> {
  const key = await subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  return subtle.verify('HMAC', key, sig, data);
}

