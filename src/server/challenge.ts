import { PasskeyInternalError } from '../errors/internal.js';
import { fromBase64Url, toBase64Url } from '../core/encoding/base64url.js';
import { encodeUtf8, decodeUtf8 } from '../core/encoding/utf8.js';
import { randomBytes } from '../core/crypto/random.js';
import { DEFAULT_CHALLENGE_TTL_MS } from './defaults.js';

/**
 * Pluggable challenge persistence. The library issues an opaque token at
 * `startRegistration` / `startAuthentication`; the caller round-trips it back
 * to `finishRegistration` / `finishAuthentication`.
 *
 * Two implementations ship out of the box:
 * - {@link InMemoryChallengeStore} — for tests and demos.
 * - {@link SignedJwtChallengeStore} — stateless, with first-class `kid`-based
 *   key rotation so secret rotation never orphans in-flight ceremonies.
 */
export interface ChallengeStore {
  /** Mint a token bound to a challenge + optional userId + ttl. */
  issue(input: { challenge: Uint8Array; userId?: Uint8Array; ttlMs: number }): Promise<string>;
  /** Consume by token — returns the challenge and removes it (single-use). */
  consume(token: string): Promise<{ challenge: Uint8Array; userId?: Uint8Array } | null>;
}

interface InMemoryEntry {
  challenge: Uint8Array;
  userId?: Uint8Array;
  expiresAt: number;
}

/**
 * Default in-memory challenge store. Single-process only. Suitable for tests
 * and single-instance demos; production multi-instance deploys should use
 * {@link SignedJwtChallengeStore} or implement {@link ChallengeStore} on Redis.
 *
 * @example
 *   const rp = new RelyingParty({ challengeStore: new InMemoryChallengeStore(), ... });
 */
export class InMemoryChallengeStore implements ChallengeStore {
  readonly #map = new Map<string, InMemoryEntry>();

  /** @inheritdoc */
  async issue(input: { challenge: Uint8Array; userId?: Uint8Array; ttlMs: number }): Promise<string> {
    const token = toBase64Url(randomBytes(32));
    this.#map.set(token, {
      challenge: input.challenge,
      ...(input.userId ? { userId: input.userId } : {}),
      expiresAt: Date.now() + input.ttlMs,
    });
    return token;
  }

  /** @inheritdoc */
  async consume(token: string): Promise<{ challenge: Uint8Array; userId?: Uint8Array } | null> {
    const entry = this.#map.get(token);
    if (!entry) return null;
    this.#map.delete(token);
    if (entry.expiresAt < Date.now()) return null;
    return entry.userId ? { challenge: entry.challenge, userId: entry.userId } : { challenge: entry.challenge };
  }

  /** Drop expired entries — call from a periodic janitor. */
  reap(now: number = Date.now()): void {
    for (const [k, v] of this.#map.entries()) {
      if (v.expiresAt < now) this.#map.delete(k);
    }
  }
}

/** Single key entry used by the JWT-backed store. */
export interface SignedJwtKeyEntry {
  /** Key identifier (kid header) — opaque, e.g. `'k-2026-04'`. */
  kid: string;
  /** HS256 secret. ≥ 32 bytes recommended. */
  secret: Uint8Array | string;
}

export interface SignedJwtChallengeStoreOptions {
  /**
   * Verify against ANY key whose `kid` appears in the JWT header. Sign new
   * tokens with the FIRST entry. To rotate: prepend the new key, leave the
   * old one until ttlMs > maxChallengeTtl.
   *
   * Single-key form (`{ secret, kid? }`) is normalized to a one-element array.
   */
  keys: ReadonlyArray<SignedJwtKeyEntry> | SignedJwtKeyEntry | { secret: Uint8Array | string; kid?: string };
  /** Default TTL applied if `issue()` does not specify one. */
  defaultTtlMs?: number;
}

/**
 * Stateless, signed-JWT challenge store with first-class key rotation. Suitable
 * for serverless and multi-instance deploys (no DB round-trip).
 *
 * Token shape: HS256 JWT with `kid` header, payload `{ ch, uid?, exp, iat }`.
 *
 * @example
 *   new SignedJwtChallengeStore({
 *     keys: [
 *       { kid: 'k-2026-04', secret: process.env.PASSKEY_SECRET_NEW! },
 *       { kid: 'k-2026-01', secret: process.env.PASSKEY_SECRET_OLD! },
 *     ],
 *   });
 */
export class SignedJwtChallengeStore implements ChallengeStore {
  readonly #keys: ReadonlyArray<{ kid: string; secret: Uint8Array }>;
  readonly #defaultTtlMs: number;
  readonly #seen = new Set<string>(); // single-use enforcement (best-effort)

  constructor(options: SignedJwtChallengeStoreOptions) {
    const raw = options.keys;
    let arr: ReadonlyArray<SignedJwtKeyEntry>;
    if (Array.isArray(raw)) {
      arr = raw;
    } else if (raw && typeof raw === 'object' && 'secret' in raw) {
      arr = [{ kid: (raw as { kid?: string }).kid ?? 'default', secret: (raw as { secret: Uint8Array | string }).secret }];
    } else {
      throw new PasskeyInternalError('SignedJwtChallengeStore: keys is required.');
    }
    if (arr.length === 0) {
      throw new PasskeyInternalError('SignedJwtChallengeStore: keys must be non-empty.');
    }
    this.#keys = arr.map((k) => ({
      kid: k.kid,
      secret: typeof k.secret === 'string' ? encodeUtf8(k.secret) : k.secret,
    }));
    this.#defaultTtlMs = options.defaultTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  }

  /** @inheritdoc */
  async issue(input: { challenge: Uint8Array; userId?: Uint8Array; ttlMs?: number }): Promise<string> {
    const active = this.#keys[0];
    if (!active) throw new PasskeyInternalError('SignedJwtChallengeStore: no active key.');
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.floor((input.ttlMs ?? this.#defaultTtlMs) / 1000);
    const header = { alg: 'HS256', typ: 'JWT', kid: active.kid };
    const payload: Record<string, unknown> = {
      ch: toBase64Url(input.challenge),
      iat: now,
      exp: now + ttl,
      jti: toBase64Url(randomBytes(16)),
    };
    if (input.userId) payload['uid'] = toBase64Url(input.userId);

    const head = toBase64Url(encodeUtf8(JSON.stringify(header)));
    const body = toBase64Url(encodeUtf8(JSON.stringify(payload)));
    const signing = `${head}.${body}`;
    const sig = await hmacSha256(active.secret, encodeUtf8(signing));
    return `${signing}.${toBase64Url(sig)}`;
  }

  /** @inheritdoc */
  async consume(token: string): Promise<{ challenge: Uint8Array; userId?: Uint8Array } | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [head, body, sigB64] = parts as [string, string, string];

    let header: { alg?: string; typ?: string; kid?: string };
    let payload: { ch?: string; uid?: string; exp?: number; iat?: number; jti?: string };
    try {
      header = JSON.parse(decodeUtf8(fromBase64Url(head))) as typeof header;
      payload = JSON.parse(decodeUtf8(fromBase64Url(body))) as typeof payload;
    } catch {
      return null;
    }
    if (header.alg !== 'HS256') return null;

    const key = this.#keys.find((k) => k.kid === header.kid);
    if (!key) return null;

    const expected = await hmacSha256(key.secret, encodeUtf8(`${head}.${body}`));
    let provided: Uint8Array;
    try {
      provided = fromBase64Url(sigB64);
    } catch {
      return null;
    }
    if (!timingSafeEqual(provided, expected)) return null;

    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < nowSec) return null;
    if (typeof payload.ch !== 'string') return null;

    if (payload.jti) {
      if (this.#seen.has(payload.jti)) return null;
      this.#seen.add(payload.jti);
      // Best-effort cap on memory growth. With 5 min TTLs and modest traffic
      // this is plenty; replace with a Redis SET for high-volume deploys.
      if (this.#seen.size > 10_000) this.#seen.clear();
    }

    let challenge: Uint8Array;
    try {
      challenge = fromBase64Url(payload.ch);
    } catch {
      return null;
    }
    let userId: Uint8Array | undefined;
    if (payload.uid) {
      try {
        userId = fromBase64Url(payload.uid);
      } catch {
        return null;
      }
    }
    return userId ? { challenge, userId } : { challenge };
  }
}

async function hmacSha256(secret: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
