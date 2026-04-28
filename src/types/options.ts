import type { AaguidString } from './webauthn.js';

/**
 * AAGUID allow/deny policy for enterprise mode. `mode` defaults to
 * `'allowlist'` when `allow` is set and `'denylist'` when only `deny` is set.
 * If both are provided, `deny` is evaluated first (deny-wins precedence).
 *
 * AAGUIDs that are not in either list are accepted under `'denylist'` and
 * rejected under `'allowlist'`. The empty AAGUID
 * `00000000-0000-0000-0000-000000000000` (returned by attestation `'none'`)
 * is treated as a special bucket — set `allowAnonymous: true` to permit it
 * under `'allowlist'`.
 */
export interface AaguidPolicy {
  mode?: 'allowlist' | 'denylist';
  allow?: ReadonlyArray<AaguidString>;
  deny?: ReadonlyArray<AaguidString>;
  allowAnonymous?: boolean;
}

/**
 * Caller-supplied signing keys for the challenge envelope. The `active` key
 * signs new envelopes; the verifier accepts any key whose `kid` matches.
 *
 * Rotation: introduce a new key in `previous` first to let in-flight
 * challenges verify against either, swap to `active` on the next deploy,
 * and drop the old key from `previous` once the TTL has elapsed (default 5
 * min). This prevents the orphaned-in-flight-ceremony bug that single-secret
 * rotations cause (PLAN §9.5).
 */
export interface ChallengeSigningKeys {
  active: { kid: string; secret: string | Uint8Array };
  previous?: ReadonlyArray<{ kid: string; secret: string | Uint8Array }>;
}
