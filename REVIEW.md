# Review Response — PR #1

Numbered log of every change made in response to Vasyl Bruhanda's review.
Test changes are deferred to the next phase per the brief.

## Blockers

### 1. Apple / FIDO-U2F verifiers rubber-stamping `valid: true`
- **Concern:** `apple.ts` and `fido-u2f.ts` returned `{ valid: true }` whenever an `x5c` was present, with zero signature / nonce / chain validation — an attacker submitting a malformed Apple or U2F attestation would succeed.
- **Files:** `src/server/attestation/apple.ts`, `src/server/attestation/fido-u2f.ts`.
- **Fix:** Both verifiers now throw `UnsupportedAttestationFormatError` (matching the `tpm.ts` / `android-key.ts` pattern). Implementing the hand-rolled ASN.1 walker for Apple and the U2F signature check is on the v0.3 roadmap; until then the dispatcher rejects rather than accepts. The default-bundle attestation path (`none` + `packed`) is unaffected.

### 2. `dummyVerify` calling `generateKey` per request
- **Concern:** `dummyVerify` ran `crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, ...)` on every unknown-credential request — orders of magnitude slower than the real `verify` it was meant to time-equalise with, inverting the timing-equalisation promise from PLAN §9.10 / §9.14.
- **Files:** `src/core/crypto/verify.ts`.
- **Fix:** Hoisted a precomputed P-256 public-key JWK (an RFC 7515 test vector — no private key implied) and lazy-cached the imported `CryptoKey` in a module-level promise. Per-request work is now exactly one `subtle.verify` call, matching the verifying branch's shape.

### 3. Challenge-envelope ceremony-check ordering leak
- **Concern:** The comment in `challenge.ts` claimed ceremony mismatch is checked AFTER tag verify "so a forged token still emits `invalid_challenge_token`", but the code threw `WrongCeremonyError` — letting an attacker who steals an `auth` envelope and replays it at the `reg` endpoint confirm the kid/secret are still live.
- **Files:** `src/server/challenge.ts`.
- **Fix:** Took option 1 from the review — moved the ceremony binding check BEFORE tag verify. Any envelope (valid or forged HMAC) carrying the wrong ceremony now deterministically yields `WrongCeremonyError`, so the error reveals nothing about signing-key liveness. Kept the distinct error class because callers genuinely benefit from being able to detect ceremony replays in their audit logs. Updated the comment to match.

### 4. Bare `as Base64Url` casts at trust boundaries
- **Concern:** `src/browser/normalize.ts:30,59` and `src/server/verify-authentication.ts:128` used unchecked `as Base64Url` casts on untrusted strings, violating the v0.1 stability rule from PLAN §4.1 / Appendix C and (in the verify-authentication case) letting an attacker-supplied `response.id` reach the store lookup without alphabet/length validation.
- **Files:** `src/browser/normalize.ts`, `src/server/verify-authentication.ts`.
- **Fix:** Replaced both with `assertBase64Url(...)`. In `verify-authentication.ts` the validation is wrapped in try/catch so a malformed id surfaces as the public `AuthenticationFailedError` (with `details.reason: 'unknown_credential'`), preserving the single-public-failure contract from §5.6; the dummy verify still runs to keep timing matched.

## High

### 5. Missing `webcrypto-shim` plumbing
- **Concern:** PLAN §6.3 / §9.11 / §3.1 specify a `core/crypto/webcrypto-shim.ts` (default) and `core/crypto/webcrypto-shim.node.ts` selected via `package.json#imports` `#webcrypto-shim` conditional alias — neither file existed and consumers called `crypto.subtle` directly, so the documented Worker / Edge / Deno portability story was undelivered.
- **Files:** added `src/core/crypto/webcrypto-shim.ts` and `src/core/crypto/webcrypto-shim.node.ts`; updated `package.json` (`imports` map), `tsconfig.json` (`paths` mapping), `src/core/crypto/verify.ts`, `src/core/crypto/digest.ts`, `src/core/crypto/random.ts`, `src/core/cose/key.ts`, `src/server/challenge.ts`.
- **Fix:** Default shim is `export const subtle = globalThis.crypto.subtle;`. The `.node.ts` variant is the only file with `import { webcrypto } from 'node:crypto'` (guarded by `/// <reference types="node" />` so the browser/edge build does not need `@types/node` everywhere). The `package.json#imports` map exposes `#webcrypto-shim` with explicit `workerd` / `edge-light` / `deno` / `browser` / `node` / `default` conditions; no `typeof process` runtime guards exist anywhere in the source.

### 6. `issueChallenge` / `verifyChallenge` naming collision
- **Concern:** PLAN §2.2 lists the helpers as `signChallengeToken` / `verifyChallengeToken`; implementation exported `issueChallenge` / `verifyChallenge`. The latter reads as "verify a WebAuthn challenge response" — confusing in auth land.
- **Files:** `src/server/challenge.ts`, `src/server/index.ts`, `src/server/generate-registration-options.ts`, `src/server/generate-authentication-options.ts`, `src/server/verify-registration.ts`, `src/server/verify-authentication.ts`.
- **Fix:** Renamed both functions to match the PLAN; updated all call sites and JSDoc cross-references.

### 7. `dom-error.ts` default mapping unknown → `not_supported`
- **Concern:** PLAN §5.4 spec table says `unknown → InternalError`. The implementation defaulted to `NotSupportedError`, which is in `FALLBACK_CODES` — so apps using the documented fallback hook would silently route unrelated bugs to the password flow.
- **Files:** `src/browser/dom-error.ts`.
- **Fix:** Default branch now returns `new InternalError(message, opts)`. Added the missing `NotAllowedError` elapsed-time disambiguation while in the file (point 16 below).

## Medium

### 8. `client-data.ts` `!==` short-circuit before `timingSafeEqualBytes`
- **Concern:** Mixing constant-time and short-circuit comparisons in ceremony code invites the wrong pattern to be copy-pasted into a key-comparison site later, even though challenges themselves are public.
- **Files:** `src/core/ceremony/client-data.ts`.
- **Fix:** Dropped the `!==` short-circuit; comparisons go through the shared `timingSafeEqualBytes` (now imported from `core/crypto/bytes.ts`) unconditionally. Single-style only.

### 9. `verify-registration.ts` `buildVerifiedEvent` dead-code & `parseCoseKey` discarded return
- **Concern:** `buildVerifiedEvent` took a `record` parameter silenced by `void record;` and accepted flag fields (`at`, `ed`) it never used. Separately, `parseCoseKey(...)` was called purely for side-effect validation with the discarded return reading awkwardly.
- **Files:** `src/server/verify-registration.ts`.
- **Fix:** Inlined the verified-event construction at the call site, deriving `credentialId` / `aaguid` / `transports` / `deviceType` from the `record` rather than passing them as redundant parameters. Hoisted the COSE-key validation into a tiny `validateCredentialKey()` helper so the discarded return is intentional and named. Cleaned up unused type imports (`AaguidString`, `Base64Url`).

### 10. Duplicated `equalBytes` / `concat` / `timingSafeEqualBytes`
- **Concern:** Three functionally-equivalent (and subtly different) helpers existed across `verify-authentication.ts`, `verify-registration.ts`, `attestation/packed.ts`, `client-data.ts`, and `challenge.ts`. Inconsistency is exactly how timing bugs creep in.
- **Files:** added `src/core/crypto/bytes.ts`; updated `src/core/ceremony/client-data.ts`, `src/server/challenge.ts`, `src/server/verify-authentication.ts`, `src/server/verify-registration.ts`, `src/server/attestation/packed.ts`.
- **Fix:** Hoisted `equalBytes`, `concatBytes`, and `timingSafeEqualBytes` into a single `core/crypto/bytes.ts` module. Removed the local copies; every site now imports the single canonical implementation.

### 11. Unsound `attStmt as { ... x5c?: Uint8Array[] }` cast
- **Concern:** `parseAttestationObject` returns `attStmt: Record<string, unknown>`; the structural cast did not actually validate that `x5c` elements are `Uint8Array`, so a malformed CBOR map would throw a generic `TypeError` instead of `InvalidAttestationError`.
- **Files:** `src/server/attestation/packed.ts` (apple/fido-u2f no longer touch `x5c` since they throw `UnsupportedAttestationFormatError`).
- **Fix:** Re-typed the local view as `Record<string, unknown>` and added an explicit `Array.isArray + every(c => c instanceof Uint8Array)` runtime guard, throwing `InvalidAttestationError` on malformed input.

### 12. `fromBase64Url` always throws `'invalid_attestation'`
- **Concern:** When the browser parses server-supplied options and a field is malformed, the user-visible `'invalid_attestation'` code is wrong (no attestation has happened yet) and misleading.
- **Files:** `src/core/encoding/base64url.ts`, `src/browser/parse-options.ts`.
- **Fix:** Added an optional `errorCode: PasskeyErrorCode` parameter to both `fromBase64Url` and `assertBase64Url` (default `'invalid_attestation'` to preserve existing behaviour). `parse-options.ts` passes `'internal_error'` at every site so malformed server options surface accurately as a server-bug class instead of an attestation failure.

## Low

### 13. Redundant `as Base64Url` casts on `toBase64Url(...)`
- **Concern:** `toBase64Url` already returns `Base64Url`; the extra cast was dead.
- **Files:** `src/server/generate-registration-options.ts`, `src/server/generate-authentication-options.ts`.
- **Fix:** Dropped both redundant casts and removed the now-unused `Base64Url` type imports.

### 14. `bytesToString` non-fatal UTF-8 decode for envelope userId
- **Concern:** The userId came from a successfully HMAC-verified envelope, so corruption is impossible in practice — but `fatal: false` would silently insert replacement characters and turn a future envelope-format bug into a silent userId mismatch instead of a loud failure.
- **Files:** `src/server/verify-registration.ts`.
- **Fix:** Switched to `fatal: true`. Trust-boundary decode now fails loud.

### 15. `NotAllowedError` always mapped to `UserCancelledError`
- **Concern:** PLAN §5.4 specifies that `NotAllowedError` should disambiguate `UserCancelledError` vs `TimeoutError` based on elapsed time (the browser uses one DOMException for both outcomes); the implementation routed every `NotAllowedError` straight to `UserCancelledError`.
- **Files:** `src/browser/dom-error.ts`, `src/browser/start-registration.ts`, `src/browser/start-authentication.ts`.
- **Fix:** `mapDomException` now accepts an optional `elapsedMs` argument; `NotAllowedError` past 30 s surfaces as `TimeoutError`. The browser ceremony entry points capture `Date.now()` before the WebCrypto call and pass the delta on rejection.

### 16. PLAN.md file-structure listing out of date
- **Concern:** PLAN §1 listed `core/cbor/decode.ts`, `core/webauthn/{auth-data,client-data,flags,transports}.ts`, and `core/time.ts`; the implementation reorganised to `core/cose/cbor.ts` + `core/ceremony/*` and dropped `time.ts` / `transports.ts`. Functionally equivalent and arguably cleaner, but the documented module map didn't match reality.
- **Files:** `PLAN.md` (§1 file listing).
- **Fix:** Updated the file-listing block to match the on-disk layout, and added the new `core/crypto/bytes.ts` module surfaced by the de-duplication work above.

## Nit

### 17. `assertBase64Url` brands the un-stripped input
- **Concern:** The validator validated the *normalized* form but branded the *original* input, so callers could end up with a `Base64Url` value still carrying `=` padding (the encoder never emits any).
- **Files:** `src/core/encoding/base64url.ts`.
- **Fix:** Strip trailing `=` padding before branding so the returned brand is consistent with the encoder.

## Notes

- All changes typecheck cleanly under `tsc --noEmit`.
- Test additions and updates are deferred to the next phase per the build-script brief.
- The Apple / FIDO-U2F roadmap (full chain validation + ASN.1 walker) is now the only material deviation from PLAN §6.4. PLAN §6.4 itself is unchanged because the roadmap statement still applies; only the verifier behaviour moved from "rubber-stamp" to "reject loudly until the chain validator lands."
