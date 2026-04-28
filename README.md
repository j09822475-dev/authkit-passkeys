# @authkit/passkeys

[![npm version](https://img.shields.io/npm/v/@authkit/passkeys.svg)](https://www.npmjs.com/package/@authkit/passkeys)
[![bundle size](https://img.shields.io/bundlephobia/minzip/@authkit/passkeys?label=browser%20gzip)](https://bundlephobia.com/package/@authkit/passkeys)
[![license](https://img.shields.io/npm/l/@authkit/passkeys.svg)](./LICENSE)
[![types](https://img.shields.io/npm/types/@authkit/passkeys.svg)](https://www.typescriptlang.org/)

A lightweight, framework-agnostic passkey/WebAuthn library for browser, Node, and edge runtimes.

**The problem.** The native WebAuthn API is correct but raw — it traffics in `ArrayBuffer`s, requires hand-rolled base64url, leaks DOM types into your server, and asks you to glue ceremony validation, attestation parsing, and counter-replay defence together yourself. Existing libraries either ship 50 KB+ server bundles dragging in `cbor` and `asn1js`, lock you into a managed service, or expose the spec as-is rather than the user flow you actually need. `@authkit/passkeys` is the opinionated middle: one pair of `start*` calls in the browser, one pair of `generate*` / `verify*` calls on the server, fully isomorphic on Web Crypto, with zero runtime dependencies.

## Features

- **Tiny.** ≤6 KB gzipped browser ceremony, ≤12 KB gzipped default server bundle (`none` + `packed` attestation; `apple` / `tpm` / `fido-u2f` / `android-key` are dynamic imports). ≤1.5 KB errors-only entry.
- **Truly isomorphic.** One server bundle runs on Node ≥18.17, Cloudflare Workers (`workerd`), Vercel Edge (`edge-light`), Deno, and Bun — no adapter layer, no `node:crypto`. Web Crypto only.
- **Zero runtime dependencies.** Hand-rolled ~1 KB CBOR decoder, hand-rolled COSE-key parser, hand-rolled ECDSA DER↔raw conversion. No `cbor`, `asn1js`, `@hexagon/base64`.
- **Stateless challenges.** Signed HMAC envelope with `kid`-aware rotation — no Redis, no ceremony cache, edge-friendly by construction.
- **Phishing-resistant defaults.** `userVerification: 'required'` (NIST AAL3 / PSD2 SCA-compatible), strict origin / RP-ID match, BE-bit regression detection, single `authentication_failed` public code so the error path is not a credential-ID enumeration oracle.
- **Conditional UI built in.** `startConditionalUI()` bundles the `AbortController`; cancel from your form-submit handler.
- **Typed end-to-end.** Branded `Base64Url` / `AaguidString` / `ChallengeToken` primitives, generic `CredentialStore<TUserId>` carries your user-id type through every server call.
- **Fallback hook.** `onFallback` notification is fired with the typed `PasskeyError` — wire your password / magic-link redirect in one place.

## Quick Start

```bash
npm install @authkit/passkeys
```

```ts
// Server (Node, Workers, Vercel Edge, Deno, Bun — same code)
import { generateAuthenticationOptions, verifyAuthentication } from '@authkit/passkeys/server';
import { createMemoryCredentialStore } from '@authkit/passkeys/storage/memory';

const store = createMemoryCredentialStore();
const signingKeys = { active: { kid: 'k1', secret: process.env.PASSKEY_SECRET! } };
const { options, challengeToken } = await generateAuthenticationOptions({
  rp: { id: 'example.com' }, store, signingKeys,
});
```

```ts
// Browser
import { startAuthentication } from '@authkit/passkeys/browser';
const response = await startAuthentication(opts);
```

## Examples

Three runnable examples live under [`examples/`](./examples). Each one drives
the full server-side ceremony end-to-end against an in-process software
authenticator stand-in for `navigator.credentials.*` — every
`@authkit/passkeys/server` call executes against the real library code, so
the output mirrors what a real browser would produce.

| Example | What it shows | Open in browser |
| --- | --- | --- |
| [`basic-usage.ts`](./examples/basic-usage.ts) | Minimal end-to-end registration + discoverable login. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/basic-usage) |
| [`advanced-usage.ts`](./examples/advanced-usage.ts) | Branded `UserId`, signing-key rotation, AAGUID allowlist, audit hooks, counter-regression guard, enumeration-oracle defence. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/advanced-usage) |
| [`with-hono.ts`](./examples/with-hono.ts) | All four ceremony endpoints behind cookie-bound challenge tokens, exercised via `app.request()` — same code runs unchanged on Workers, Vercel Edge, Deno Deploy, Bun, Node. | [![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/with-hono) |

```bash
npx tsx examples/basic-usage.ts
npx tsx examples/advanced-usage.ts
npx tsx examples/with-hono.ts
```

The StackBlitz buttons open self-contained sandboxes from
[`examples/sandbox/`](./examples/sandbox) — each subdirectory is a standalone
npm project (`package.json` + `tsconfig.json` + `index.ts` + `README`) that
installs `@authkit/passkeys` from the registry.

## API Reference

The library is split across four published entry points so tree-shaking can drop the side you don't use.

### `@authkit/passkeys/browser`

Browser-only ceremony helpers. Wrap `navigator.credentials.create / get`.

#### `startRegistration(options, init?)`

```ts
function startRegistration(
  options: RegistrationOptionsJSON,
  init?: RegisterInit,
): Promise<RegistrationResponseJSON>;

interface RegisterInit {
  signal?: AbortSignal;
  onFallback?: (err: PasskeyError) => void | Promise<void>;
}
```

Run the WebAuthn registration ceremony. Accepts the JSON shape produced by `generateRegistrationOptions`, performs base64url decoding internally, returns a JSON-safe attestation response ready to POST back. The optional `onFallback` is fire-and-forget — it is invoked immediately before the typed `PasskeyError` is rethrown; it does not swallow the rejection.

```ts
import { startRegistration, isPasskeyError } from '@authkit/passkeys/browser';

const opts = await fetch('/api/passkey/register/options').then((r) => r.json());
try {
  const response = await startRegistration(opts, {
    onFallback: (err) => analytics.track('passkey_register_failed', { code: err.code }),
  });
  await fetch('/api/passkey/register/verify', { method: 'POST', body: JSON.stringify(response) });
} catch (err) {
  if (isPasskeyError(err) && err.code === 'not_supported') router.push('/login/password');
}
```

Throws: `NotSupportedError`, `UserCancelledError`, `TimeoutError`, `InvalidStateError`, `SecurityError`.

#### `startAuthentication(options, init?)`

```ts
function startAuthentication(
  options: AuthenticationOptionsJSON,
  init?: AuthenticateInit,
): Promise<AuthenticationResponseJSON>;

interface AuthenticateInit extends RegisterInit {
  mediation?: 'conditional' | 'optional' | 'required';
}
```

Run the authentication ceremony. Pass `mediation: 'conditional'` to enable autofill UI — callers must gate the conditional path on `isConditionalUISupported()` first. The WebAuthn `'silent'` mediation is intentionally excluded; it does not apply to passkey flows.

```ts
import { startAuthentication, isConditionalUISupported } from '@authkit/passkeys/browser';

if (await isConditionalUISupported()) {
  const ctrl = new AbortController();
  const opts = await fetch('/api/passkey/login/options').then((r) => r.json());
  startAuthentication(opts, { mediation: 'conditional', signal: ctrl.signal })
    .then(handleLogin).catch(() => {});
  form.addEventListener('submit', () => ctrl.abort());
}
```

#### `startConditionalUI(options, init?)`

```ts
function startConditionalUI(
  options: AuthenticationOptionsJSON,
  init?: Omit<AuthenticateInit, 'mediation' | 'signal'>,
): { result: Promise<AuthenticationResponseJSON>; cancel(): void };
```

Convenience wrapper that runs `startAuthentication` with `mediation: 'conditional'` and bundles the `AbortController` so callers can cancel cleanly when the user picks a non-passkey path.

```ts
const { result, cancel } = startConditionalUI(opts);
form.addEventListener('submit', cancel);
const response = await result;
```

#### `isPasskeySupported()` · `isConditionalUISupported()` · `isPlatformAuthenticatorAvailable()`

```ts
function isPasskeySupported(): boolean;
function isConditionalUISupported(): Promise<boolean>;
function isPlatformAuthenticatorAvailable(): Promise<boolean>;
```

Synchronous and async feature detection.

```ts
if (!isPasskeySupported()) return router.push('/login/password');
const builtIn = await isPlatformAuthenticatorAvailable();
```

#### `parseRegistrationOptions(json)` · `parseAuthenticationOptions(json)`

```ts
function parseRegistrationOptions(json: RegistrationOptionsJSON): PublicKeyCredentialCreationOptions;
function parseAuthenticationOptions(json: AuthenticationOptionsJSON): PublicKeyCredentialRequestOptions;
```

Polyfills for the still-not-everywhere `PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON`. Useful when you want to call `navigator.credentials.create` yourself but keep the JSON wire format.

### `@authkit/passkeys/server`

Server-only ceremony helpers. Runs on Node ≥18.17, Cloudflare Workers (`workerd`), Vercel Edge (`edge-light`), Deno, Bun.

#### `generateRegistrationOptions(input)`

```ts
function generateRegistrationOptions<TUserId extends string>(
  input: GenerateRegistrationInput<TUserId>,
): Promise<{ options: RegistrationOptionsJSON; challengeToken: ChallengeToken }>;
```

Builds the registration options JSON the browser passes to `navigator.credentials.create`, plus a stateless signed challenge envelope. The store is consulted only to populate `excludeCredentials` — no mutation; the call site owns the transaction boundary on `verifyRegistration` → `store.create`.

```ts
const { options, challengeToken } = await generateRegistrationOptions({
  rp: { id: 'example.com', name: 'Example' },
  user: { id: user.id, name: user.email, displayName: user.name },
  store, signingKeys: PASSKEY_SIGNING_KEYS,
});
setCookie('passkey_reg', challengeToken, { httpOnly: true, sameSite: 'strict', maxAge: 300 });
return Response.json(options);
```

#### `generateAuthenticationOptions(input)`

```ts
function generateAuthenticationOptions<TUserId extends string>(
  input: GenerateAuthenticationInput<TUserId>,
): Promise<{ options: AuthenticationOptionsJSON; challengeToken: ChallengeToken }>;
```

Pass `user` for non-discoverable flows; omit it for the discoverable / passkey-first flow (the user is identified after the ceremony from the stored `CredentialRecord`, no enumeration leak).

```ts
const { options, challengeToken } = await generateAuthenticationOptions({
  rp: { id: 'example.com' }, store, signingKeys: PASSKEY_SIGNING_KEYS,
});
```

#### `verifyRegistration(input)`

```ts
function verifyRegistration(input: VerifyRegistrationInput): Promise<NewCredentialRecord>;
```

Verifies the attestation and returns a `NewCredentialRecord` ready for storage. The store is **not** written automatically — call `store.create(record)` from your app code so you control the transaction (e.g. wrapping with the user-creation row).

```ts
const record = await verifyRegistration({
  response: req.body,
  challengeToken: getCookie('passkey_reg')!,
  expectedOrigin: 'https://example.com',
  expectedRpId: 'example.com',
  signingKeys: PASSKEY_SIGNING_KEYS,
});
await store.create({ ...record, userId: req.user.id });
```

#### `verifyAuthentication(input)`

```ts
function verifyAuthentication<TUserId extends string>(
  input: VerifyAuthenticationInput<TUserId>,
): Promise<VerifiedAuthentication<TUserId>>;
```

Verifies the assertion. The single-public-`authentication_failed` contract holds end-to-end: unknown credential, signature mismatch, malformed signature, and BE-bit regression all surface as `AuthenticationFailedError` with the granular reason on `error.details.reason` for server logs only. The unknown-credential branch runs a synthetic `dummyVerify` so request duration matches the verifying branch.

```ts
const result = await verifyAuthentication({
  response: req.body,
  challengeToken: getCookie('passkey_auth')!,
  expectedOrigin: 'https://example.com',
  expectedRpId: 'example.com',
  store, signingKeys: PASSKEY_SIGNING_KEYS,
});
await store.updateCounter(result.credential.credentialId, result.newCounter);
await session.create(result.userId);
```

#### `signChallengeToken(input)` · `verifyChallengeToken(token, signingKeys, ceremony, expectedUserId?)`

Lower-level access to the signed challenge envelope. You will rarely call these directly — `generate*` and `verify*` already do. Useful when you want to issue a challenge from a different transport than the one you verify on.

#### `verifyAttestation(attestation, ctx, overrides?)`

Dispatches attestation verification by `fmt`. Static formats (`none`, `packed`) resolve synchronously; `fido-u2f`, `apple`, `tpm`, `android-key` are loaded via dynamic import the first time they are seen. Pass an `overrides` map for tests or enterprise opt-ins.

#### `assertAaguidAllowed(policy, aaguid)` · `assertUserVerification(flags, requireUv)`

Standalone policy primitives — wired into `verifyRegistration` / `verifyAuthentication` automatically, exported so you can apply them outside the standard ceremony.

#### Defaults

```ts
DEFAULT_TIMEOUT_MS              // 60_000
DEFAULT_CHALLENGE_TTL_MS        // 5 * 60_000
MIN_CHALLENGE_TTL_MS            // 30_000
MAX_CHALLENGE_TTL_MS            // 10 * 60_000
DEFAULT_CHALLENGE_BYTES         // 32
DEFAULT_USER_VERIFICATION       // 'required'
DEFAULT_PUB_KEY_CRED_ALG_NAMES  // ['ES256', 'EdDSA', 'RS256']
```

### `@authkit/passkeys/storage/memory` · `@authkit/passkeys/storage/types`

```ts
function createMemoryCredentialStore<TUserId extends string = string>(): CredentialStore<TUserId>;

interface CredentialStore<TUserId extends string = string> {
  create(record: NewCredentialRecord<TUserId>): Promise<CredentialRecord<TUserId>>;
  findByCredentialId(credentialId: Base64Url): Promise<CredentialRecord<TUserId> | null>;
  listByUserId(userId: TUserId): Promise<ReadonlyArray<CredentialRecord<TUserId>>>;
  updateCounter(credentialId: Base64Url, newCounter: number): Promise<void>;
  updateBackupState(credentialId: Base64Url, backupState: boolean): Promise<void>;
  deleteByCredentialId(credentialId: Base64Url): Promise<void>;
}
```

The in-memory store is testing-only — single-process. Production deployments implement `CredentialStore` over their own database. The interface is intentionally small (six methods) and round-trips every field of `CredentialRecord` so downstream MDS3 policies, replay defence, and BS-bit observability all keep working.

### `@authkit/passkeys/errors`

Zero-cost error contract — import only this entry to type-narrow errors without pulling the ceremony code.

```ts
import { isPasskeyError, FALLBACK_CODES } from '@authkit/passkeys/errors';

if (isPasskeyError(err) && FALLBACK_CODES.has(err.code)) router.push('/login/password');
```

Exports every concrete error class (`NotSupportedError`, `UserCancelledError`, `TimeoutError`, `InvalidStateError`, `SecurityError`, `InvalidChallengeTokenError`, `WrongCeremonyError`, `InvalidChallengeError`, `InvalidOriginError`, `InvalidRpIdError`, `AuthenticationFailedError`, `InvalidAttestationError`, `UnsupportedAlgorithmError`, `UnsupportedAttestationFormatError`, `CounterRegressionError`, `UserVerificationRequiredError`, `AaguidNotAllowedError`, `StorageError`, `InternalError`), the `PasskeyError` base class, the `isPasskeyError` type guard, the `PasskeyErrorCode` union, the static `ERROR_MESSAGES` map, and the `FALLBACK_CODES` set.

`PasskeyError.toJSON()` returns `{ code, message }` only — `cause`, `details`, and stack frames are stripped because they may carry server-internal info.

### `@authkit/passkeys/types`

Pure type re-exports — runtime-free. Import these in shared types packages without dragging the ceremony bundle.

## Framework Guides

The v0.1 release ships the runtime-agnostic primitives. Wiring is a few lines per framework — first-class adapters (`/adapters/next`, `/adapters/hono`, `/adapters/express`) are on the v0.2 roadmap.

### Next.js (App Router)

```ts
// app/api/passkey/login/options/route.ts
import { generateAuthenticationOptions } from '@authkit/passkeys/server';
import { cookies } from 'next/headers';
import { store, signingKeys } from '@/lib/passkey';

export async function POST() {
  const { options, challengeToken } = await generateAuthenticationOptions({
    rp: { id: process.env.RP_ID! }, store, signingKeys,
  });
  cookies().set('passkey_auth', challengeToken, {
    httpOnly: true, secure: true, sameSite: 'strict', maxAge: 300, path: '/',
  });
  return Response.json(options);
}
```

```ts
// app/api/passkey/login/verify/route.ts
import { verifyAuthentication } from '@authkit/passkeys/server';
import { isPasskeyError } from '@authkit/passkeys/errors';
import { cookies } from 'next/headers';

export async function POST(req: Request) {
  const challengeToken = cookies().get('passkey_auth')?.value;
  if (!challengeToken) return new Response('Forbidden', { status: 401 });
  try {
    const result = await verifyAuthentication({
      response: await req.json(),
      challengeToken,
      expectedOrigin: process.env.ORIGIN!,
      expectedRpId: process.env.RP_ID!,
      store, signingKeys,
    });
    await store.updateCounter(result.credential.credentialId, result.newCounter);
    await createSession(result.userId);
    return Response.json({ ok: true });
  } catch (err) {
    if (isPasskeyError(err)) return Response.json(err.toJSON(), { status: 401 });
    throw err;
  }
}
```

The `/server` entry resolves under the `edge-light` and `workerd` conditions, so this works unchanged on Vercel Edge runtime and Cloudflare Pages.

### Express

```ts
import express from 'express';
import { generateAuthenticationOptions, verifyAuthentication } from '@authkit/passkeys/server';
import { isPasskeyError } from '@authkit/passkeys/errors';

const app = express().use(express.json());

app.post('/api/passkey/login/options', async (_req, res) => {
  const { options, challengeToken } = await generateAuthenticationOptions({
    rp: { id: 'example.com' }, store, signingKeys,
  });
  res.cookie('passkey_auth', challengeToken, {
    httpOnly: true, secure: true, sameSite: 'strict', maxAge: 5 * 60_000,
  });
  res.json(options);
});

app.post('/api/passkey/login/verify', async (req, res) => {
  try {
    const result = await verifyAuthentication({
      response: req.body,
      challengeToken: req.cookies.passkey_auth,
      expectedOrigin: 'https://example.com',
      expectedRpId: 'example.com',
      store, signingKeys,
    });
    await store.updateCounter(result.credential.credentialId, result.newCounter);
    res.json({ userId: result.userId });
  } catch (err) {
    if (isPasskeyError(err)) return res.status(401).json(err.toJSON());
    throw err;
  }
});
```

### Hono (Cloudflare Workers / Vercel Edge / Deno / Bun)

```ts
import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';
import { generateAuthenticationOptions, verifyAuthentication } from '@authkit/passkeys/server';
import { isPasskeyError } from '@authkit/passkeys/errors';

const app = new Hono<{ Bindings: { PASSKEY_SECRET: string } }>();

app.post('/api/passkey/login/options', async (c) => {
  const { options, challengeToken } = await generateAuthenticationOptions({
    rp: { id: 'example.com' }, store,
    signingKeys: { active: { kid: 'k1', secret: c.env.PASSKEY_SECRET } },
  });
  setCookie(c, 'passkey_auth', challengeToken, {
    httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 300,
  });
  return c.json(options);
});

app.post('/api/passkey/login/verify', async (c) => {
  try {
    const result = await verifyAuthentication({
      response: await c.req.json(),
      challengeToken: getCookie(c, 'passkey_auth')!,
      expectedOrigin: 'https://example.com',
      expectedRpId: 'example.com',
      store,
      signingKeys: { active: { kid: 'k1', secret: c.env.PASSKEY_SECRET } },
    });
    await store.updateCounter(result.credential.credentialId, result.newCounter);
    return c.json({ userId: result.userId });
  } catch (err) {
    if (isPasskeyError(err)) return c.json(err.toJSON(), 401);
    throw err;
  }
});
```

The same `Hono` app boots unchanged on Workers, Deno Deploy, Bun, and Vercel Edge — there is no Node-specific code path under the hood.

## Configuration

### `generateRegistrationOptions(input)`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `rp` | `{ id, name }` | required | Relying-party identity. `id` is the eTLD+1 (no scheme, no port). |
| `user` | `{ id, name, displayName }` | required | User entity. `id` is your stable user-id (string). |
| `store` | `CredentialStore<TUserId>` | required | Used to populate `excludeCredentials`. |
| `signingKeys` | `ChallengeSigningKeys` | required | HMAC secret(s) for the stateless challenge envelope. |
| `pubKeyCredAlgs` | `CoseAlgName[]` | `['ES256','EdDSA','RS256']` | COSE algorithm preference order. |
| `userVerification` | `'required' \| 'preferred' \| 'discouraged'` | `'required'` | UV requirement. NIST AAL3 / PSD2 SCA defaults to `'required'`. |
| `residentKey` | `'required' \| 'preferred' \| 'discouraged'` | `'preferred'` | Discoverable-credential preference. |
| `authenticatorAttachment` | `'platform' \| 'cross-platform'` | unset | Lets the platform pick when omitted. |
| `timeout` | `number` (ms) | `60_000` | Browser ceremony timeout. |
| `attestation` | `'none' \| 'indirect' \| 'direct' \| 'enterprise'` | `'none'` | Attestation conveyance. |
| `challengeTtlMs` | `number` (ms) | `300_000` | Envelope TTL. Min `30_000`, max `600_000`. |

### `generateAuthenticationOptions(input)`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `rp` | `{ id }` | required | Relying-party id. |
| `user` | `{ id }` | undefined | Omit for discoverable / passkey-first flows. |
| `store` | `CredentialStore<TUserId>` | required | Used to populate `allowCredentials` when `user` is set. |
| `signingKeys` | `ChallengeSigningKeys` | required | HMAC secret(s). |
| `userVerification` | `'required' \| 'preferred' \| 'discouraged'` | `'required'` | Same default rationale as registration. |
| `timeout` | `number` (ms) | `60_000` | Browser timeout. |
| `challengeTtlMs` | `number` (ms) | `300_000` | Envelope TTL. |

### `verifyRegistration(input)` / `verifyAuthentication(input)`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `response` | `RegistrationResponseJSON` / `AuthenticationResponseJSON` | required | Browser response. |
| `challengeToken` | `ChallengeToken \| string` | required | Token from `generate*Options`. |
| `expectedOrigin` | `string \| readonly string[]` | required | Allow-list. Multiple origins are matched verbatim — no wildcards. |
| `expectedRpId` | `string` | required | Must match `authData.rpIdHash` byte-for-byte. |
| `signingKeys` | `ChallengeSigningKeys` | required | Same keys the issuer used. |
| `requireUserVerification` | `boolean` | `true` | Set `false` only for non-https dev. |
| `onVerified` | `(ev) => void \| Promise<void>` | undefined | Audit hook fired after verification but before return. |
| `policy` (registration) | `AaguidPolicy` | undefined | Optional AAGUID allow/deny rules. |
| `attestationVerifiers` (registration) | `ReadonlyMap<string, AttestationVerifier>` | undefined | Override registry — short-circuits the dynamic-import path. |

### `ChallengeSigningKeys`

```ts
interface ChallengeSigningKeys {
  active: { kid: string; secret: string | Uint8Array };
  previous?: ReadonlyArray<{ kid: string; secret: string | Uint8Array }>;
}
```

Rotate by introducing the new key in `previous` first, swapping to `active` on the next deploy, and dropping the old key from `previous` once `challengeTtlMs` has elapsed. Single-secret rotations strand in-flight ceremonies; this scheme does not.

### `AaguidPolicy`

```ts
interface AaguidPolicy {
  mode?: 'allowlist' | 'denylist';     // defaults from which fields are set
  allow?: ReadonlyArray<AaguidString>;
  deny?: ReadonlyArray<AaguidString>;  // deny wins when both are set
  allowAnonymous?: boolean;            // permits the all-zero AAGUID under allowlist
}
```

## TypeScript Features

- **Branded primitives.** `Base64Url`, `AaguidString`, and `ChallengeToken` are nominal — you cannot pass a raw `string` where `Base64Url` is expected. The library mints them via `toBase64Url(Uint8Array)` / `assertBase64Url(string)`; ESLint should forbid `as Base64Url` casts in app code.
- **Generic user-id propagation.** Every server call is parameterised on `TUserId extends string`, so `verifyAuthentication(...)` returns `userId: TUserId` (your branded `UserId`, not `string`).

  ```ts
  type UserId = string & { readonly __brand: 'UserId' };
  const store: CredentialStore<UserId> = createMemoryCredentialStore<UserId>();
  const { userId } = await verifyAuthentication<UserId>({ /* … */ });
  // userId: UserId  ← carried through; not widened to string
  ```
- **Stable error contract.** `PasskeyErrorCode` is a closed string union — adding a code is a minor version, removing or renaming one is major. The `FALLBACK_CODES` set is the canonical "fall back to password / magic-link" subset.
- **Discriminated `details.reason`.** Granular failure causes (`unknown_credential`, `invalid_signature`, `challenge_expired`, `sign_count_regressed`, …) live on `error.details.reason` for server logs, never on `error.code`. `toJSON()` strips them so they cannot accidentally reach the wire.
- **DOM-free server bundle.** Server types reuse library-owned mirrors (`PasskeyExtensionInputsJSON`, `PasskeyExtensionResultsJSON`) instead of leaking `lib.dom.d.ts` into a Workers module.
- **`exactOptionalPropertyTypes`-clean.** All optional fields are spread conditionally — building the library with `exactOptionalPropertyTypes: true` is a no-op for callers.

## Comparison vs. Other Libraries

| | `@authkit/passkeys` | `@simplewebauthn/{server,browser}` | `@github/webauthn-json` | `fido2-lib` | `@passwordless-id/webauthn` |
| --- | --- | --- | --- | --- | --- |
| **Browser bundle** (gzip) | **≤6 KB** | ~13 KB browser, ES5 polyfills | ~3 KB | n/a (no browser entry) | ~5 KB |
| **Server bundle** (gzip) | **≤12 KB** default | ~50 KB+ (drags `cbor`, `asn1js`, `@hexagon/base64`) | n/a | ~80 KB, Node-only | ~10 KB |
| **Runtime deps** | **0** | `cbor`, `@hexagon/base64`, `@peculiar/asn1-*` | 0 | `@peculiar/asn1-*`, `cbor`, `node:crypto` | 0 |
| **Edge runtimes** (Workers / Vercel Edge / Deno) | **First-class** (one bundle) | Yes via JSR | Browser-only | **No** (`node:crypto`) | Yes |
| **API shape** | One pair of `start*` + one pair of `verify*` (mirrored names) | Spec-mirroring helpers | Browser JSON conversion only | Low-level FIDO2 primitives | Concise, isomorphic |
| **Conditional UI** | `startConditionalUI()` with bundled abort | Manual `mediation: 'conditional'` | Manual | n/a | Manual |
| **Counter / BE-regression / replay defence** | Built-in | Built-in | n/a | Manual | Partial |
| **Stateless challenge envelope** | **Built-in** (HMAC, kid-aware rotation) | Caller-managed | n/a | Caller-managed | Caller-managed |
| **`onFallback` notification hook** | Built-in | No | No | No | No |
| **Branded `Base64Url` / `AaguidString` types** | Yes | No (raw `string`) | No | No | No |
| **`authentication_failed` collapsed code** (no enumeration oracle) | Yes | No | n/a | No | No |
| **Status** | Active | De-facto standard | **Deprecated** | Stable, low-level | Sporadic updates |

Commercial alternatives (Hanko, Corbado, Stytch, Auth0, Clerk) charge per-MAU and own your credential storage; `@authkit/passkeys` is the open-source path when you want to keep the database, the cookies, and the cost flat.

## Roadmap

- v0.2: framework adapters (`/adapters/next`, `/adapters/hono`, `/adapters/express`, `/adapters/fastify`), React/Vue hooks, ORM storage adapters (Prisma, Drizzle, Kysely).
- v0.3: MDS3 metadata client (`/mds`), enterprise attestation (TPM, Android Key full chain), conformance-suite green run.

## Contributing

Issues and PRs welcome. Run the test suite with `npm test`, the type check with `npm run typecheck`, and the bundle-budget check with `npm run size` before sending a PR. The `PLAN.md` in this repo is the canonical architecture document — read its §9 (security invariants) before changing anything in `verify-authentication.ts` or the challenge envelope.

## License

[MIT](./LICENSE) © Mykhailo Kryvytskyi
