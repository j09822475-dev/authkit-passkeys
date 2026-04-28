# Changelog

All notable changes to `@authkit/passkeys` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-28

Initial public release.

### Added

- **Browser ceremony entry** (`@authkit/passkeys/browser`).
  - `startRegistration(options, init?)` — wraps `navigator.credentials.create`; accepts the JSON shape produced by the server, performs base64url decoding internally, returns a JSON-safe attestation response.
  - `startAuthentication(options, init?)` — wraps `navigator.credentials.get`; supports `mediation: 'conditional' | 'optional' | 'required'`. The WebAuthn `'silent'` value is intentionally excluded.
  - `startConditionalUI(options, init?)` — bundles an `AbortController` for clean cancellation when the user picks a non-passkey path.
  - `isPasskeySupported()`, `isConditionalUISupported()`, `isPlatformAuthenticatorAvailable()` feature-detection helpers.
  - `parseRegistrationOptions(json)`, `parseAuthenticationOptions(json)` — polyfills for the not-yet-everywhere native `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`.
  - `onFallback(err)` notification hook on every ceremony — fired with the typed `PasskeyError` immediately before it is rethrown.
- **Server ceremony entry** (`@authkit/passkeys/server`). Single isomorphic bundle running on Node ≥18.17, Cloudflare Workers (`workerd`), Vercel Edge (`edge-light`), Deno, and Bun via Web Crypto only.
  - `generateRegistrationOptions(input)` and `generateAuthenticationOptions(input)` build the browser-facing JSON plus a stateless signed challenge envelope.
  - `verifyRegistration(input)` returns a `NewCredentialRecord` ready for storage; the store is **not** mutated automatically — the call site owns the transaction boundary.
  - `verifyAuthentication(input)` collapses unknown-credential and signature-mismatch into the single public `authentication_failed` code; runs `dummyVerify` on the unknown branch so request duration does not branch on credential existence.
  - `signChallengeToken(input)` and `verifyChallengeToken(token, signingKeys, ceremony, expectedUserId?)` — HMAC-SHA-256 envelope with `kid`-aware rotation, ceremony binding (`'reg'` / `'auth'`), expiry, and optional user binding.
  - Attestation registry — `none` and `packed` ship in the default bundle; `apple`, `tpm`, `fido-u2f`, and `android-key` are dynamic imports (separate chunks) so the default bundle stays under 12 KB gzipped.
  - `assertAaguidAllowed(policy, aaguid)` — deny-wins precedence with `allowAnonymous` opt-in for the all-zero AAGUID emitted by attestation `'none'`.
  - `assertUserVerification(flags, requireUv)` — UP/UV enforcement.
  - Defaults: 60 s ceremony timeout, 5-min challenge TTL (min 30 s, max 10 min), 32-byte challenge length, `userVerification: 'required'`, algorithm preference `['ES256', 'EdDSA', 'RS256']`.
- **Storage** (`@authkit/passkeys/storage/memory`, `@authkit/passkeys/storage/types`).
  - `CredentialStore<TUserId>` interface generic on the caller's branded user-id type.
  - `createMemoryCredentialStore<TUserId>()` — single-process testing-only store; surfaces duplicate inserts as `InvalidStateError`.
- **Errors entry** (`@authkit/passkeys/errors`).
  - `PasskeyError` base class with stable `.code` and JSON-safe `toJSON()` that strips `cause`, `details`, and stack frames.
  - 19 concrete error subclasses pinned to one `PasskeyErrorCode` each: `NotSupportedError`, `UserCancelledError`, `TimeoutError`, `InvalidStateError`, `SecurityError`, `InvalidChallengeTokenError`, `WrongCeremonyError`, `InvalidChallengeError`, `InvalidOriginError`, `InvalidRpIdError`, `AuthenticationFailedError`, `InvalidAttestationError`, `UnsupportedAlgorithmError`, `UnsupportedAttestationFormatError`, `CounterRegressionError`, `UserVerificationRequiredError`, `AaguidNotAllowedError`, `StorageError`, `InternalError`.
  - `isPasskeyError(value)` cross-realm type guard.
  - `FALLBACK_CODES` set — the canonical "fall back to password / magic-link" subset (`not_supported`, `user_cancelled`, `timeout`, `authentication_failed`).
  - Static `ERROR_MESSAGES` map — no template-interpolated user input on the wire.
- **Types entry** (`@authkit/passkeys/types`). Pure type re-exports, runtime-free. Branded `Base64Url`, `AaguidString`, `ChallengeToken`. Library-owned mirrors of the WebAuthn JSON shapes (`RegistrationOptionsJSON`, `AuthenticationOptionsJSON`, `RegistrationResponseJSON`, `AuthenticationResponseJSON`, extension input/output mirrors) so the server module never imports `lib.dom.d.ts`.
- **Core primitives** (internal, not a published entry).
  - ~1 KB hand-rolled CBOR decoder (maps, arrays, byte/text strings, uint, nint, tagged, float16/32/64) — replaces `cbor`.
  - Hand-rolled COSE-key parser (`parseCoseKey`, `importCoseKey`) — replaces `asn1js`.
  - Hand-rolled ECDSA DER ↔ raw `r||s` conversion — required because COSE/WebAuthn ship DER signatures but Web Crypto wants raw.
  - `webcrypto-shim` with `workerd` / `edge-light` / `deno` / `browser` / `node` export conditions; the Node-specific shim is the only path that touches `node:crypto`, and it is unreachable from any non-Node bundle.
- **Defaults pinned for fintech / healthcare audiences.** `userVerification: 'required'` (NIST AAL3, PSD2 SCA-compatible), `attestation: 'none'` for consumer flows, single-public-`authentication_failed` to avoid credential-ID enumeration via timing or error-shape analysis, BE-bit regression detection (1 → 0 forbidden), counter-regression detection.
- **Bundle budgets enforced in CI.** `dist/browser/index.js` ≤ 6 KB, `dist/server/index.js` ≤ 12 KB, `dist/errors/index.js` ≤ 1.5 KB.
- **MIT license.**

### Known limitations

- Framework adapters (`/adapters/next`, `/adapters/hono`, `/adapters/express`, `/adapters/fastify`, `/adapters/nestjs`, `/adapters/trpc`) are roadmap items — wire `generate*` / `verify*` directly using the framework guides in `README.md`. Targeted for v0.2.
- React / Vue / SvelteKit hooks are roadmap items. Targeted for v0.2.
- ORM storage adapters (Prisma, Drizzle, Kysely) are roadmap items. The interface (`CredentialStore<TUserId>`) is stable; only the in-memory implementation ships in v0.1. Targeted for v0.2.
- MDS3 metadata client (`/mds`) is a roadmap item. AAGUID policy works without it. Targeted for v0.3.
- `apple`, `tpm`, `fido-u2f`, and `android-key` attestation verifiers ship as dynamic-import stubs in v0.1; the dispatcher routes through them but full chain validation lands in v0.3 alongside the FIDO conformance suite.
