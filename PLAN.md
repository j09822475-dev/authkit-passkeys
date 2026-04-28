# `@authkit/passkeys` — Architecture Plan

> Lightweight, framework-agnostic Passkey/WebAuthn library targeting Browser + Node + Edge.
> Headline marketing target: **<10KB gzipped client core**. Server core is a separate concern at **<15KB gzipped** (Worker bundles include `/server`, so the README must spell this out and never quote 10KB as a single overall number). WebAuthn Level 3 first, no `cbor`/`asn1js`/`@hexagon/base64`.
>
> Differentiation vs `@simplewebauthn`: opinionated user-flow API (one `startRegistration()` / `startAuthentication()` browser pair, mirroring server method names, instead of six functions), zero `node:crypto` (pure WebCrypto), custom 1KB COSE-key parser, framework adapters in the box, first-class `onFallback` hooks for password/magic-link degradation.

---

## 1. Project Structure

```
authkit-passkeys/
├── package.json                      # Public manifest, exports map, sideEffects:false
├── tsconfig.json                     # ES2022, NodeNext, strict, declarationMap
├── tsconfig.build.json               # Extends tsconfig — emit only src/**, exclude tests
├── tsup.config.ts                    # Multi-entry ESM+CJS build; per-entry treeshake
├── vitest.config.ts                  # Workspace: node + jsdom + happy-dom projects
├── vitest.workspace.ts               # Per-runtime test projects (node, browser, edge)
├── .gitignore
├── .npmignore                        # Excludes tests/, examples/, .github/
├── .changeset/                       # Changesets for versioned releases
├── README.md                         # Quickstart + API overview
├── PLAN.md                           # This document
├── LICENSE                           # MIT
│
├── src/                              # All TypeScript source — published via dist/
│   ├── index.ts                      # Root barrel: re-exports types, errors, version
│   │
│   ├── core/                         # Runtime-agnostic primitives (works in any JS env with WebCrypto)
│   │   ├── index.ts                  # Internal-only barrel for core
│   │   │
│   │   ├── encoding/
│   │   │   ├── base64url.ts          # toBase64Url / fromBase64Url (Uint8Array <-> string), no deps
│   │   │   ├── utf8.ts               # encodeUtf8 / decodeUtf8 wrappers around TextEncoder/Decoder
│   │   │   ├── hex.ts                # toHex / fromHex (used for AAGUID display)
│   │   │   └── index.ts              # Barrel
│   │   │
│   │   ├── cose/                     # Custom minimal CBOR + COSE-key parser (~1KB total)
│   │   │   ├── cbor.ts               # decodeCbor() — supports map/array/bytes/text/uint/nint/tagged. No encode.
│   │   │   ├── algorithms.ts         # COSE_ALG enum + algorithm ↔ Web Crypto params mapping
│   │   │   ├── key.ts                # parseCoseKey() → typed COSE key + importIntoWebCrypto()
│   │   │   └── index.ts
│   │   │
│   │   ├── crypto/                   # WebCrypto-only crypto helpers (no node:crypto, no @noble/* in core)
│   │   │   ├── random.ts             # randomBytes(length) → Uint8Array via crypto.getRandomValues
│   │   │   ├── digest.ts             # sha256(data) via crypto.subtle.digest
│   │   │   ├── verify.ts             # verifySignature(coseKey, signature, data) — multi-alg dispatcher
│   │   │   ├── der.ts                # ECDSA r||s ↔ DER-SEQUENCE conversion (Web Crypto wants raw, COSE gives DER)
│   │   │   └── index.ts
│   │   │
│   │   ├── ceremony/                 # Pure parsing/validation — no I/O, no storage
│   │   │   ├── client-data.ts        # parseClientDataJSON + assertExpectedClientData(challenge, origin, type)
│   │   │   ├── auth-data.ts          # parseAuthenticatorData → flags + counter + AAGUID + credentialPublicKey
│   │   │   ├── attestation.ts        # parseAttestationObject → fmt + authData + attStmt; no fmt-specific verify in core
│   │   │   ├── flags.ts              # decodeFlags(byte) → { up, uv, be, bs, at, ed }
│   │   │   ├── rp-id.ts              # validateRpId(origin, rpId) — covers subdomain rules + scheme checks
│   │   │   └── index.ts
│   │   │
│   │   ├── attestation-formats/      # Lazy-loaded fmt verifiers; tree-shaken if unused
│   │   │   ├── none.ts               # Trivial pass-through
│   │   │   ├── packed.ts             # Self + ECDAA + x5c packed attestation
│   │   │   ├── fido-u2f.ts           # Legacy u2f attestation
│   │   │   ├── apple.ts              # Apple anonymous attestation (App Attest related)
│   │   │   ├── android-key.ts        # Stub w/ explicit unsupported error (out of MVP)
│   │   │   ├── tpm.ts                # Stub w/ explicit unsupported error (out of MVP)
│   │   │   └── index.ts              # Map<fmt, verifier> with optional registry
│   │   │
│   │   ├── result.ts                 # Result<T, E> tagged union + ok()/err() helpers
│   │   ├── invariant.ts              # Internal invariant() — throws PasskeyInternalError on logic bugs
│   │   └── version.ts                # __PACKAGE_VERSION__ injected by tsup at build
│   │
│   ├── server/                       # Relying-Party (server) API — runs in Node 18+, edge, Deno, Bun
│   │   ├── index.ts                  # Public exports: RelyingParty (single entry point) + types
│   │   ├── relying-party.ts          # RelyingParty class — central config + methods + resolveConfig hook
│   │   ├── options-registration.ts   # _buildRegistrationOptions() — INTERNAL helper used by RelyingParty
│   │   ├── options-authentication.ts # _buildAuthenticationOptions() — INTERNAL
│   │   ├── verify-registration.ts    # _verifyRegistration() — INTERNAL
│   │   ├── verify-authentication.ts  # _verifyAuthentication() — INTERNAL
│   │   ├── challenge.ts              # ChallengeStore interface + InMemoryChallengeStore + SignedJwtChallengeStore (kid-based key rotation)
│   │   ├── credential-store.ts       # CredentialStore interface — user-supplied
│   │   ├── policies.ts               # AuthenticatorPolicy + AuthenticatorPolicyOverride (explicit per-field optional)
│   │   ├── audit.ts                  # AuditHook type + emitAudit() helper
│   │   ├── node-crypto-shim.ts       # Node-only WebCrypto shim — selected ONLY under default Node export condition
│   │   └── defaults.ts               # Sensible RP defaults (timeout, AS, attestation:'none', UV='required', etc.)
│   │
│   ├── browser/                      # Client (user agent) API — runs only in browser
│   │   ├── index.ts                  # Public exports: startRegistration, startAuthentication, ...
│   │   ├── start-registration.ts     # startRegistration(serverOptions, opts?) — full ceremony wrapper
│   │   ├── start-authentication.ts   # startAuthentication(serverOptions, opts?) — incl. conditional mediation
│   │   ├── feature-detect.ts         # isPasskeySupported / isConditionalUISupported / isPlatformAuthenticatorAvailable
│   │   ├── parse-options.ts          # parseCreationOptionsFromJSON / parseRequestOptionsFromJSON
│   │   │                              # (uses native if present, falls back to manual base64url decode)
│   │   ├── serialize-response.ts     # toJSON() polyfill for PublicKeyCredential when needed
│   │   ├── abort.ts                  # AbortController helpers — esp. for canceling conditional mediation
│   │   └── prf.ts                    # WebAuthn PRF extension helpers (Level 3)
│   │
│   ├── types/                        # All public types live here for explicit import path
│   │   ├── index.ts                  # Barrel — used by `@authkit/passkeys/types`
│   │   ├── webauthn-json.ts          # JSON shapes + library-owned PasskeyExtensionsInput / Output (no DOM-lib leakage on server boundaries)
│   │   ├── ceremony.ts               # ParsedAttestation, ParsedAssertion, AuthenticatorData
│   │   ├── credential.ts             # CredentialRecord, StoredPublicKey, BackupState
│   │   ├── policy.ts                 # AuthenticatorPolicy, AuthenticatorPolicyOverride, RpConfig
│   │   ├── flags.ts                  # AuthenticatorFlags
│   │   └── transport.ts              # AuthenticatorTransport union
│   │
│   ├── errors/                       # Error class hierarchy + codes
│   │   ├── index.ts                  # Barrel
│   │   ├── base.ts                   # PasskeyError extends Error — code/cause/details
│   │   ├── codes.ts                  # PasskeyErrorCode enum + map to messages
│   │   ├── client.ts                 # PasskeyClientError (browser-side: NotSupported, UserCancelled, etc.)
│   │   ├── verification.ts           # PasskeyVerificationError (server-side: BadChallenge, BadOrigin, BadSignature, ReplayDetected)
│   │   ├── policy.ts                 # PasskeyPolicyError (AAGUID denied, UV required missing)
│   │   └── internal.ts               # PasskeyInternalError — should never reach user (logic bug)
│   │
│   ├── adapters/                     # Framework integrations — each subpath ESM-tree-shakes independently
│   │   ├── next/
│   │   │   ├── index.ts              # createPasskeyRouteHandler() — App Router GET/POST
│   │   │   └── middleware.ts         # createPasskeyMiddleware() for Next middleware
│   │   ├── hono/
│   │   │   └── index.ts              # passkeyApp() — Hono sub-app w/ /options, /verify routes
│   │   ├── express/
│   │   │   └── index.ts              # passkeyRouter() — Express Router
│   │   ├── fastify/
│   │   │   └── index.ts              # passkeyPlugin — Fastify plugin
│   │   ├── nestjs/
│   │   │   ├── index.ts
│   │   │   ├── passkey.module.ts
│   │   │   ├── passkey.guard.ts
│   │   │   └── passkey.decorator.ts  # @Passkey() decorator
│   │   ├── trpc/
│   │   │   └── index.ts              # passkeyProcedure builder
│   │   ├── react/
│   │   │   ├── index.ts
│   │   │   ├── use-passkey.ts        # usePasskey() — register/authenticate state machine
│   │   │   ├── passkey-button.tsx    # <PasskeyButton mode="register|authenticate" />
│   │   │   └── passkey-input.tsx     # <PasskeyInput /> — conditional UI autofill
│   │   ├── vue/
│   │   │   ├── index.ts
│   │   │   └── use-passkey.ts        # Vue 3 composable
│   │   └── sveltekit/
│   │       └── index.ts              # createPasskeyActions() — SvelteKit form actions + load helper
│   │
│   ├── storage/                      # Reference CredentialStore implementations
│   │   ├── memory.ts                 # In-memory (tests / demos)
│   │   ├── prisma.ts                 # Prisma adapter (peerDep: @prisma/client)
│   │   ├── drizzle.ts                # Drizzle adapter (peerDep: drizzle-orm)
│   │   ├── kysely.ts                 # Kysely adapter (peerDep: kysely)
│   │   └── index.ts                  # Barrel of all adapters
│   │
│   └── mds/                          # MDS3 (FIDO Metadata Service) — opt-in, lazy
│       ├── index.ts                  # createMdsClient(), MdsAuthenticatorPolicy
│       ├── client.ts                 # fetchAndVerifyBlob() — JWS verification of metadata BLOB
│       ├── jws.ts                    # Minimal JWS parser (no `jose` dep — uses WebCrypto)
│       ├── policy.ts                 # MdsAaguidPolicy: allow-list / deny-list / status filter
│       └── cache.ts                  # MdsCache interface + MemoryMdsCache
│
├── tests/                            # Vitest tests; mirrors src/ tree
│   ├── core/
│   │   ├── encoding.test.ts
│   │   ├── cose.test.ts
│   │   ├── crypto.test.ts
│   │   └── ceremony.test.ts
│   ├── server/
│   │   ├── verify-registration.test.ts
│   │   ├── verify-authentication.test.ts
│   │   ├── policies.test.ts
│   │   └── relying-party.test.ts
│   ├── browser/
│   │   ├── register.test.ts          # Mocks navigator.credentials
│   │   ├── authenticate.test.ts
│   │   └── feature-detect.test.ts
│   ├── adapters/
│   │   ├── react.test.tsx            # @testing-library/react
│   │   ├── hono.test.ts
│   │   └── next.test.ts
│   ├── e2e/
│   │   └── round-trip.test.ts        # Mock authenticator → server verify → re-authenticate
│   └── fixtures/                     # Real ceremony JSONs for regression tests
│       ├── chrome-platform-auth/
│       ├── safari-icloud/
│       ├── windows-hello/
│       ├── yubikey-5/
│       └── android-google-pm/
│
├── benchmarks/
│   └── verify.bench.ts               # Vitest bench — verifyAuthenticationResponse perf budget
│
├── examples/                         # Not published; consumed via examples on docs site
│   ├── nextjs-app-router/
│   ├── hono-cloudflare-workers/
│   ├── express-prisma/
│   └── react-spa-vite/
│
└── .github/
    └── workflows/
        ├── ci.yml                    # Lint + typecheck + test (Node 18/20/22) + edge tests + bundle size guard
        └── release.yml               # Changesets-based publishing
```

### Why this layout

- **`core/` is the foundation** — pure, no env-specific code. `server/` and `browser/` import from `core/`, never the other way.
- **`types/` is a public barrel** — consumers import types via `@authkit/passkeys/types` for clean isolation in monorepos that share types between server and browser code.
- **`adapters/*` and `storage/*` live behind subpath exports** — installing the lib never pulls peer-dep code unless you import the adapter.
- **`attestation-formats/*` are individual files** — bundlers can tree-shake unused formats. Most apps need only `none` + `packed`.
- **`mds/` is fully optional** — gated behind `@authkit/passkeys/mds`; MDS3 BLOB parsing is enterprise-only.

---

## 2. Public API Design

### 2.1 Server — `RelyingParty`

```ts
import { RelyingParty } from '@authkit/passkeys/server';

const rp = new RelyingParty({
  rpName: 'Acme',
  rpId: 'acme.com',                          // covers acme.com + *.acme.com
  origin: ['https://acme.com', 'https://app.acme.com'],
  defaultTimeoutMs: 60_000,
  challengeStore,                             // see ChallengeStore below
  credentialStore,                            // see CredentialStore below
  policy: {
    userVerification: 'required',             // DEFAULT (NIST AAL3 / PSD2 SCA-friendly). Opt out to 'preferred' for consumer-grade flows.
    residentKey: 'preferred',
    authenticatorAttachment: undefined,       // any
    aaguidAllowList: undefined,
    transports: ['internal', 'hybrid', 'usb', 'nfc', 'ble'],
  },
  audit: (event) => logger.info(event),
});

// Multi-tenant / per-request RP config (replaces the v0.0 standalone-functions form).
// Anything returned by resolveConfig overrides the constructor defaults for that ceremony.
const multiTenantRp = new RelyingParty({
  rpName: 'AcmeCloud',
  challengeStore,
  credentialStore,
  resolveConfig: async (ctx) => {
    const tenant = await tenants.lookup(ctx.hostname);
    return { rpId: tenant.rpId, origin: tenant.allowedOrigins };
  },
});
```

#### `class RelyingParty`

```ts
/**
 * Central handle for a Relying Party. Holds shared config and exposes the four
 * ceremony methods. Stateless except via its injected ChallengeStore/CredentialStore.
 *
 * @example
 *   const rp = new RelyingParty({ rpId: 'acme.com', origin: 'https://acme.com', ... });
 *   const opts = await rp.startRegistration({ user: { id, name, displayName } });
 */
export class RelyingParty {
  constructor(config: RpConfig);

  /**
   * Build options for `navigator.credentials.create()`. Persists the challenge
   * via the configured ChallengeStore so it can be verified in finishRegistration.
   *
   * @param input.user           User record being registered (id, name, displayName)
   * @param input.excludeCredentials  Existing credentials to exclude (avoid re-registering same authenticator)
   * @param input.attestation    'none' | 'indirect' | 'direct' | 'enterprise' (default: 'none')
   * @param input.extensions     Optional WebAuthn extensions (PRF, credProps, largeBlob)
   * @returns                    JSON-serializable options + challenge token
   */
  startRegistration(input: StartRegistrationInput): Promise<StartRegistrationOutput>;

  /**
   * Verify the browser's registration response, parse the credential public key,
   * apply the configured policy, and (on success) hand back a CredentialRecord
   * the caller persists via CredentialStore.
   *
   * Returns a Result — never throws on validation failure (only on programmer error).
   *
   * @param input.response       PublicKeyCredentialJSON returned by register()
   * @param input.challengeToken Token returned from startRegistration
   * @param input.expectedUserId Sanity check — must match the user that started the ceremony
   */
  finishRegistration(
    input: FinishRegistrationInput,
  ): Promise<Result<CredentialRecord, PasskeyVerificationError | PasskeyPolicyError>>;

  /**
   * Build options for `navigator.credentials.get()`. Supports discoverable-credential
   * (passwordless) flow when allowCredentials is empty.
   */
  startAuthentication(input?: StartAuthenticationInput): Promise<StartAuthenticationOutput>;

  /**
   * Verify the assertion. On success: returns the matched credential and the new
   * sign-counter the caller MUST persist (atomically with session creation).
   */
  finishAuthentication(
    input: FinishAuthenticationInput,
  ): Promise<Result<AuthenticatedCredential, PasskeyVerificationError | PasskeyPolicyError>>;
}
```

#### Single entry point — no standalone `generate*/verify*` functions

`RelyingParty` is the **only** public server entry. The earlier `generateRegistrationOptions` / `verifyRegistrationResponse` / `generateAuthenticationOptions` / `verifyAuthenticationResponse` standalone exports have been **removed** — they tripled the public API surface (three docs pages, three test matrices) for a use case (multi-tenant / per-request config) that the `resolveConfig` callback now covers cleanly. The functions still exist as private `_buildRegistrationOptions` / `_verifyRegistration` helpers inside `server/`, but are not re-exported from `server/index.ts`.

#### `StartRegistrationInput` / `Output`

```ts
export interface StartRegistrationInput {
  user: { id: Uint8Array; name: string; displayName: string };  // Uint8Array per spec; helpers in core/encoding for string round-trips
  excludeCredentials?: Array<{ id: string; transports?: AuthenticatorTransport[] }>;
  attestation?: AttestationConveyancePreference;
  extensions?: PasskeyExtensionsInput;          // library-owned type — never the DOM-lib AuthenticationExtensionsClientInputs
  policy?: AuthenticatorPolicyOverride;         // explicit per-field optional, NOT structural Partial<>
  timeoutMs?: number;
}

export interface StartRegistrationOutput {
  /** JSON-serializable — pass directly to `register(options)` on the client. */
  options: PublicKeyCredentialCreationOptionsJSON;
  /**
   * Opaque token (encoded challenge + ttl + binding to userId) the caller must round-trip
   * back to finishRegistration. Independent of cookie/session — usable in stateless flows.
   */
  challengeToken: string;
}
```

#### `FinishRegistrationInput` / Result

```ts
export interface FinishRegistrationInput {
  response: PublicKeyCredentialJSON;       // RegistrationResponseJSON shape
  challengeToken: string;
  expectedUserId: Uint8Array;              // canonical Uint8Array — no UTF-8 lossy decode at the boundary
  /** Override RP-level policy for this single verification. */
  policy?: AuthenticatorPolicyOverride;
}

/** What the caller persists. CredentialStore.save(record) */
export interface CredentialRecord {
  credentialId: string;                    // base64url
  userId: Uint8Array;                      // canonical bytes per spec; never lossily decoded to UTF-8
  publicKey: Uint8Array;                   // SPKI-encoded; passkey can re-import via WebCrypto
  publicKeyAlgorithm: COSEAlgorithmIdentifier;
  signCount: number;
  /**
   * `true` iff this authenticator is known to always return `signCount === 0`
   * (iCloud Keychain, Google Password Manager, etc.). On registration we set
   * this to `null` (unknown); `verifyAuthenticationResponse` flips it to `true`
   * the first time it observes a 0-counter assertion, and to `false` otherwise.
   * Policy code uses it to skip the "counter must increase" check for known-static authenticators.
   */
  signCountStatic: boolean | null;
  transports: AuthenticatorTransport[];
  aaguid: string;                          // hex-formatted UUID
  backupEligible: boolean;
  backupState: boolean;
  attestationFormat: string;
  createdAt: Date;
}
```

### 2.2 Browser — `startRegistration` / `startAuthentication`

Names mirror the server methods (`RelyingParty.startRegistration` / `.startAuthentication`) so a developer reading both halves of the ceremony reads the same verb. The previous draft used `register` / `authenticate`, which collided with `lit-element`'s `register`, OAuth `authenticate`, and most React component naming — every consumer would have written `import { register as registerPasskey }`.

```ts
import { startRegistration, startAuthentication, isPasskeySupported } from '@authkit/passkeys/browser';

if (!isPasskeySupported()) {
  // graceful fallback
}

// 1. Fetch options from server (returns startRegistration output)
const { options, challengeToken } = await fetch('/api/passkey/start-registration')
  .then((r) => r.json());

// 2. Run ceremony
const credential = await startRegistration(options, {
  signal: abortController.signal,
});

// 3. POST credential back, server.finishRegistration verifies
await fetch('/api/passkey/finish-registration', {
  method: 'POST',
  body: JSON.stringify({ challengeToken, response: credential }),
});
```

#### `startRegistration`

```ts
/**
 * Run the full registration ceremony. Wraps `navigator.credentials.create()` with
 * - automatic JSON ↔ ArrayBuffer parsing (via parseCreationOptionsFromJSON when present)
 * - native toJSON() of the resulting credential (with polyfill fallback)
 * - typed errors mapped to PasskeyClientError codes
 *
 * @param options    Either a JSON shape from server.startRegistration OR a native
 *                   PublicKeyCredentialCreationOptions. Auto-detected.
 * @param opts.signal           AbortSignal for cancellation.
 * @returns          RegistrationResponseJSON ready to POST back to server.
 * @throws PasskeyClientError   With one of: 'not-supported', 'user-cancelled',
 *                              'invalid-state' (already registered), 'security-error',
 *                              'timeout', 'unknown'.
 */
export function startRegistration(
  options: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialCreationOptions,
  opts?: { signal?: AbortSignal },
): Promise<RegistrationResponseJSON>;
```

#### `startAuthentication`

```ts
/**
 * Run the full authentication ceremony.
 *
 * @param options    Either JSON or native PublicKeyCredentialRequestOptions.
 * @param opts.useAutofill   When true, requests `mediation: 'conditional'` — the browser
 *                           shows passkeys as autofill in a username input; the promise
 *                           settles only when the user picks one. Combine with
 *                           AbortController to cancel when the user submits a password instead.
 * @param opts.signal        AbortSignal — required when useAutofill is true.
 * @returns      AuthenticationResponseJSON
 */
export function startAuthentication(
  options: PublicKeyCredentialRequestOptionsJSON | PublicKeyCredentialRequestOptions,
  opts?: { signal?: AbortSignal; useAutofill?: boolean },
): Promise<AuthenticationResponseJSON>;
```

#### Feature detection

```ts
/** True if `window.PublicKeyCredential` exists. */
export function isPasskeySupported(): boolean;

/** True if `PublicKeyCredential.isConditionalMediationAvailable()` resolves to true. */
export function isConditionalUISupported(): Promise<boolean>;

/** True if the device has a built-in (platform) authenticator (Touch ID, Face ID, Windows Hello). */
export function isPlatformAuthenticatorAvailable(): Promise<boolean>;

/** True if the browser exposes `parseCreationOptionsFromJSON`. */
export function hasNativeJsonHelpers(): boolean;
```

### 2.3 React adapter — `usePasskey()` + `<PasskeyButton />`

```tsx
import { usePasskey, PasskeyButton } from '@authkit/passkeys/react';

function LoginScreen() {
  const passkey = usePasskey({
    startUrl: '/api/passkey/start-authentication',
    finishUrl: '/api/passkey/finish-authentication',
    onSuccess: (session) => router.push('/dashboard'),
    onError: (err) => toast.error(err.message),
    // First-class fallback hook (mirrors the differentiator from the research report).
    // Fires on any code in FALLBACK_REASONS: 'not-supported', 'user-cancelled',
    // 'no-credentials', 'authentication-failed', 'timeout'.
    onFallback: (reason) => switchToPasswordLogin(reason),
  });

  return (
    <PasskeyButton
      mode="authenticate"
      controller={passkey}
      conditionalUI                // browser autofill
      fallback={<MagicLinkLogin />}
    >
      Sign in with passkey
    </PasskeyButton>
  );
}
```

```ts
/**
 * Hook that drives a passkey ceremony state machine.
 *
 * State: 'idle' | 'starting' | 'awaiting-user' | 'verifying' | 'success' | 'error' | 'fallback'
 *
 * - Uses startUrl/finishUrl convention by default; override fetcher for custom transport.
 * - Auto-cancels in-flight conditional-UI request on unmount.
 * - When the ceremony fails with a known fallback reason, transitions to 'fallback' and
 *   invokes onFallback(reason) so callers can switch UI to password / magic-link.
 */
export function usePasskey<TSuccess = unknown>(opts: UsePasskeyOptions<TSuccess>): {
  state: PasskeyState;
  error: PasskeyError | null;
  register: () => Promise<TSuccess>;
  authenticate: (opts?: { useAutofill?: boolean }) => Promise<TSuccess>;
  reset: () => void;
};

export interface UsePasskeyOptions<TSuccess> {
  startUrl: string;
  finishUrl: string;
  onSuccess?: (value: TSuccess) => void;
  onError?: (err: PasskeyError) => void;
  /** Fired when the ceremony fails in a way the caller should degrade gracefully. */
  onFallback?: (reason: PasskeyErrorCode) => void;
  fetcher?: typeof fetch;
}
```

#### Non-React adapters: same `onFallback` contract

Hono / Next / Express adapters expose the equivalent hook on their handler config:

```ts
passkeyApp({
  rp,
  onAuthenticated: async (c, cred) => { /* ... */ },
  onFallback: (c, reason) => c.json({ fallback: 'password', reason }, 200),
});
```

The handler invokes `onFallback` for the same set of reason codes; if not provided it returns the default `{ ok: false, error }` body unchanged.

### 2.4 Hono adapter

```ts
import { Hono } from 'hono';
import { passkeyApp } from '@authkit/passkeys/adapters/hono';

const app = new Hono();
app.route('/auth/passkey', passkeyApp({ rp, onAuthenticated: async (c, cred) => {
  await c.set('session', await createSession(cred.userId));
}}));
```

### 2.5 Next.js App Router adapter

```ts
// app/api/passkey/[...action]/route.ts
import { createPasskeyRouteHandler } from '@authkit/passkeys/adapters/next';
export const { GET, POST } = createPasskeyRouteHandler({ rp, onAuthenticated });
```

### 2.6 Storage adapter (Prisma example)

```ts
import { PrismaCredentialStore } from '@authkit/passkeys/storage/prisma';
const credentialStore = new PrismaCredentialStore(prisma, {
  // optional column mapping for legacy schemas
  modelName: 'passkeyCredential',
});
```

`CredentialStore` interface (user-supplied or use a built-in adapter):

```ts
export interface CredentialStore {
  /** Look up by credentialId — used during authentication. */
  findById(credentialId: string): Promise<CredentialRecord | null>;
  /** Look up all credentials for a user — used during registration to fill excludeCredentials. */
  findByUserId(userId: string): Promise<CredentialRecord[]>;
  /** Persist a brand-new credential. MUST reject if credentialId already exists (uniqueness invariant). */
  save(record: CredentialRecord): Promise<void>;
  /** Update sign-count after each authentication. MUST be atomic with session creation if possible. */
  updateSignCount(credentialId: string, signCount: number): Promise<void>;
  /** Delete a credential (user-initiated revoke). */
  delete(credentialId: string): Promise<void>;
}
```

`ChallengeStore` interface:

```ts
export interface ChallengeStore {
  /** Mint a token bound to a challenge + optional userId + ttl. */
  issue(input: { challenge: Uint8Array; userId?: string; ttlMs: number }): Promise<string>;
  /** Consume by token — returns the challenge and removes it (single-use). */
  consume(token: string): Promise<{ challenge: Uint8Array; userId?: string } | null>;
}
```

Default implementations: `InMemoryChallengeStore` (testing), `SignedJwtChallengeStore` (stateless — HS256, no DB round-trip).

`SignedJwtChallengeStore` ships with **first-class key rotation** so fintech consumers can rotate the signing secret without orphaning in-flight registrations:

```ts
new SignedJwtChallengeStore({
  // Verify against ANY key whose kid appears in the JWT header.
  // Sign new tokens with the FIRST entry (= "active" key).
  // To rotate: prepend the new key, leave the old one until ttlMs > maxChallengeTtl.
  keys: [
    { kid: 'k-2026-04', secret: process.env.PASSKEY_CHALLENGE_SECRET_NEW! },
    { kid: 'k-2026-01', secret: process.env.PASSKEY_CHALLENGE_SECRET_OLD! },
  ],
  ttlMs: 5 * 60_000,
});
```

Tokens are emitted with a `kid` JOSE header; verify-time we look up by `kid` and reject with `bad-challenge` if no key matches. A single-key constructor form (`{ secret, kid? }`) remains for the simple case but is internally normalized to a one-element `keys` array.

### 2.7 Errors as values

Every public method that performs verification returns `Result<T, PasskeyError>` instead of throwing. Programmer errors (missing config, wrong types) throw `PasskeyInternalError` synchronously.

**Public-boundary collapsing for security-sensitive codes.** To prevent credential-id enumeration via timing/error-shape oracles (see §9.10), `finishAuthentication` collapses `unknown-credential` and `bad-signature` into a single public-facing code `'authentication-failed'`. The granular reason is available on `error.details.reason` for **server-internal logging only** — never echo `details` to the client. Callers MUST NOT branch UX on `details.reason`.

```ts
const result = await rp.finishAuthentication(input);
if (!result.ok) {
  switch (result.error.code) {
    case 'bad-challenge':                  // challenge expired or never issued
    case 'bad-origin':
    case 'bad-rp-id':
    case 'authentication-failed':          // collapses unknown-credential + bad-signature
    case 'replay-detected':                // sign-counter regressed on a non-static authenticator
    case 'aaguid-not-allowed':
    case 'user-verification-required':
      auditLog.warn(result.error.code, result.error.details); // details.reason is server-only
      return reject({ code: result.error.code });             // never forward .details to client
  }
}
return accept(result.value);
```

Registration uses the same pattern (`registration-failed` collapses parse/signature/attestation failures at the public boundary; granular reason in `details`).

---

## 3. Internal Architecture

### 3.1 Module dependency graph

```
              ┌────────────────────────────────────────────┐
              │                  errors/                   │ ← imported by everyone
              └────────────────────────────────────────────┘
                            ▲                 ▲
                            │                 │
              ┌────────────────────┐ ┌────────────────┐
              │       types/       │ │     core/      │ ← only WebCrypto + TextEncoder/Decoder
              └────────────────────┘ └────────────────┘
                       ▲                     ▲    ▲
       ┌───────────────┘                     │    │
       │                                     │    │
┌──────────────┐                       ┌──────────┐ ┌──────────┐
│   server/    │ ────────────────────▶ │  core/   │ │ browser/ │
└──────────────┘                       └──────────┘ └──────────┘
       ▲                                     ▲          ▲
       │                                     │          │
   storage/, mds/, adapters/server      core/utils    adapters/react,vue,sveltekit
```

Hard rules enforced via ESLint `no-restricted-imports`:

- `errors/` is the **only** module every layer is allowed to depend on (it sits below `core/` in the diagram). The ESLint rule lists `errors/` as an explicit allow-list exception — do not infer it implicitly.
- `core/*` MUST NOT import from `server/`, `browser/`, `adapters/`, `storage/`, `mds/`. (May import from `errors/` and `types/`.)
- `server/*` MUST NOT import from `browser/`.
- `browser/*` MUST NOT import from `server/`.
- `adapters/<framework>/*` may import `server/` OR `browser/` but not both within one adapter.

### 3.2 Data flow — registration ceremony

```
client                            server                            store
─────                             ──────                            ─────
                                  startRegistration(user)
                                  ├── randomBytes(32) → challenge
                                  ├── challengeStore.issue → token
                                  └── return options + token
  ◀────── options + token ──────  ◀────────────────────────────
register(options)
├── parseCreationOptionsFromJSON
├── navigator.credentials.create
└── credential.toJSON() ─────────▶ finishRegistration({response, token})
                                  ├── challengeStore.consume(token)
                                  ├── parseClientDataJSON
                                  │   └── assert: type/origin/challenge
                                  ├── parseAttestationObject
                                  │   ├── parseAuthenticatorData
                                  │   │   ├── assert: rpIdHash
                                  │   │   └── decode flags
                                  │   └── parseAttestationStatement
                                  │       └── verify (per fmt)
                                  ├── parseCoseKey → SPKI
                                  ├── policy.check
                                  └── return CredentialRecord ────▶ store.save()
```

### 3.3 Data flow — authentication ceremony

```
client                            server                            store
─────                             ──────                            ─────
                                  startAuthentication()
                                  ├── randomBytes(32) → challenge
                                  ├── allowCredentials? → store.findByUserId
                                  └── challengeStore.issue
  ◀────── options + token ──────  ◀────────────────────────────
authenticate(options)
├── navigator.credentials.get
└── assertion.toJSON() ──────────▶ finishAuthentication({response, token})
                                  ├── challengeStore.consume
                                  ├── store.findById(credentialId) ──▶ get record
                                  ├── parseClientDataJSON.assert
                                  ├── parseAuthenticatorData
                                  │   ├── assert: rpIdHash
                                  │   └── flags
                                  ├── verifySignature(coseKey, sig, authData||sha256(clientDataJSON))
                                  ├── replay check: newCount > oldCount
                                  ├── policy.check
                                  └── return AuthenticatedCredential
                                                           │
                                                           └─── store.updateSignCount(...)
```

### 3.4 Key design patterns

- **Result type for verification** — verification returns `Result<T, E>`, exposing structured error codes without try/catch noise. Programmer errors still throw.
- **Pluggable stores** — `ChallengeStore` and `CredentialStore` are injected. Default in-memory + signed-JWT (with kid-based key rotation) shipped.
- **Strategy pattern for attestation formats** — `attestation-formats/` exports a registry; `RelyingParty` accepts a custom registry to add/replace verifiers. Unused formats tree-shake out.
- **Single public entry point per layer** — `RelyingParty` is the one server entry; multi-tenant / per-request config flows through its `resolveConfig` callback. No standalone `generate*/verify*` exports — adapters build on `RelyingParty` only.
- **Adapter pattern** — framework adapters wrap the core lib without coupling it to any framework.
- **Tagged unions everywhere** — `Result`, error codes, ceremony states are all discriminated unions to maximize TS narrowing.

---

## 4. Type System

### 4.1 Core primitives

```ts
// errors/codes.ts
//
// Public surface — consumers may switch on these. Adding new codes is a minor
// version bump (see §5.3). `'authentication-failed'` and `'registration-failed'`
// are aggregate codes that intentionally hide enumeration-leaking details — see §9.10.
export type PasskeyErrorCode =
  | 'not-supported'
  | 'user-cancelled'
  | 'invalid-state'
  | 'security-error'
  | 'timeout'
  | 'no-credentials'
  | 'bad-challenge'
  | 'bad-origin'
  | 'bad-rp-id'
  | 'authentication-failed'      // collapses internal 'unknown-credential' + 'bad-signature'
  | 'registration-failed'        // collapses internal parse / signature / attestation failures
  | 'replay-detected'
  | 'aaguid-not-allowed'
  | 'user-verification-required'
  | 'transport-not-allowed'
  | 'unsupported-attestation-format'
  | 'malformed-response'
  | 'unknown';

/**
 * Internal-only reason strings carried on `error.details.reason` for server
 * audit logs. NEVER returned as the top-level `error.code`. Treat these as
 * unstable — they may change between minor versions.
 */
export type PasskeyInternalReason =
  | 'unknown-credential'
  | 'bad-signature'
  | 'cose-key-parse-failed'
  | 'attestation-statement-invalid';

// errors/base.ts
export class PasskeyError extends Error {
  readonly code: PasskeyErrorCode;
  readonly details?: Record<string, unknown>;
  constructor(code: PasskeyErrorCode, message: string, options?: { cause?: unknown; details?: Record<string, unknown> });
}

// core/result.ts
export type Result<T, E = PasskeyError> = { ok: true; value: T } | { ok: false; error: E };
export const ok = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
```

### 4.2 WebAuthn JSON shapes

We re-export browser's native types where available and define our own as fallbacks for environments without `lib.dom.d.ts`:

```ts
// types/webauthn-json.ts
export interface PublicKeyCredentialCreationOptionsJSON {
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;                                // base64url
  pubKeyCredParams: { alg: COSEAlgorithmIdentifier; type: 'public-key' }[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
  hints?: ('security-key' | 'client-device' | 'hybrid')[];
}

export interface PublicKeyCredentialDescriptorJSON {
  id: string;
  type: 'public-key';
  transports?: AuthenticatorTransport[];
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: AuthenticatorAttestationResponseJSON;
  clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
  authenticatorAttachment?: AuthenticatorAttachment;
}
// ... AuthenticationResponseJSON identically structured
```

### 4.3 Generics in CredentialStore

`CredentialStore` is generic over an extension type so consumers can attach app-specific metadata:

```ts
export interface CredentialStore<TExt extends Record<string, unknown> = {}> {
  findById(credentialId: string): Promise<(CredentialRecord & TExt) | null>;
  findByUserId(userId: string): Promise<(CredentialRecord & TExt)[]>;
  save(record: CredentialRecord & TExt): Promise<void>;
  updateSignCount(credentialId: string, signCount: number): Promise<void>;
  delete(credentialId: string): Promise<void>;
}
```

### 4.4 Conditional types — `Awaited<RpReturn>`

```ts
// Helper to extract success-arm type from a Result-returning method
export type Verified<F extends (...a: any) => Promise<Result<any, any>>> =
  Awaited<ReturnType<F>> extends { ok: true; value: infer V } ? V : never;

type AuthSuccess = Verified<RelyingParty['finishAuthentication']>;
// → AuthenticatedCredential
```

### 4.5 Compile-time enforcement

- `strict: true`, `noUncheckedIndexedAccess: true`, `exactOptionalPropertyTypes: true`.
- All public-API parameters use named-property objects (no positional bools).
- `as const` on lookup tables (algorithms, error codes) → literal-typed unions.
- `verbatimModuleSyntax: true` to keep `import type` strictly type-only (helps tree-shaking).
- Branded types for sensitive primitives:
  ```ts
  export type ChallengeToken = string & { readonly __brand: 'ChallengeToken' };
  export type CredentialId = string & { readonly __brand: 'CredentialId' };
  ```
- **Explicit per-field optional types for overrides.** `AuthenticatorPolicyOverride` is hand-written rather than `Partial<AuthenticatorPolicy>` so a typo (`userVerifaction: 'required'`) is rejected at compile time instead of silently widened by `Partial<>`'s structural rules under `exactOptionalPropertyTypes`:
  ```ts
  export interface AuthenticatorPolicyOverride {
    userVerification?: UserVerificationRequirement;
    residentKey?: ResidentKeyRequirement;
    authenticatorAttachment?: AuthenticatorAttachment;
    aaguidAllowList?: readonly string[];
    aaguidDenyList?: readonly string[];
    transports?: readonly AuthenticatorTransport[];
    // … explicit per field, no index signature, no spread-friendly Partial
  }
  ```
  At the API boundary `RelyingParty` ALSO calls `assertKnownPolicyKeys(input.policy)` at runtime as a defense-in-depth check for callers using the JS API without TS strict mode.

---

## 5. Error Handling Strategy

### 5.1 When to throw vs return Result

| Situation                                 | Behavior                                       |
| ----------------------------------------- | ---------------------------------------------- |
| Missing/invalid configuration             | **throw** `PasskeyInternalError` synchronously |
| Browser-side ceremony (user-cancelled,    | **throw** `PasskeyClientError`                 |
| timeout, NotSupportedError, …)            | (mirrors `navigator.credentials.*` behavior)   |
| Server-side verification failure          | **return** `Result.err(PasskeyVerificationError)` |
| Server-side policy violation              | **return** `Result.err(PasskeyPolicyError)`    |
| Malformed input (e.g. bad base64url)      | **return** `Result.err(...code: 'malformed-response')` |
| Logic bugs (unreachable code)             | **throw** `PasskeyInternalError`               |

Rationale: server-side verification is high-throughput; throw/catch in hot paths is awkward and hides codes from logging. Browser ceremony is low-throughput and we want to feel like the native API.

### 5.2 Error classes

```ts
class PasskeyError extends Error { code: PasskeyErrorCode; details?: ... }
class PasskeyClientError       extends PasskeyError { /* user-cancelled, timeout, … */ }
class PasskeyVerificationError extends PasskeyError { /* bad-challenge, bad-signature, … */ }
class PasskeyPolicyError       extends PasskeyError { /* aaguid-not-allowed, uv-required, … */ }
class PasskeyInternalError     extends PasskeyError { /* logic bugs */ }
```

All errors include an optional `details` object: `{ aaguid?, credentialId?, expectedOrigin?, actualOrigin?, … }` for structured logging without leaking PII.

### 5.3 Error-code guarantees

`PasskeyErrorCode` is the public contract. We commit to:

- Never silently change a code's semantics.
- Adding new codes is a minor version bump.
- Removing/renaming a code is a major version bump.

### 5.4 Browser error mapping

Native `DOMException`s from `navigator.credentials.*` map to library codes:

| DOMException name      | Mapped code           |
| ---------------------- | --------------------- |
| `NotSupportedError`    | `not-supported`       |
| `NotAllowedError`      | `user-cancelled`      |
| `InvalidStateError`    | `invalid-state`       |
| `SecurityError`        | `security-error`      |
| `TimeoutError`         | `timeout`             |
| `AbortError`           | `user-cancelled`      |
| anything else          | `unknown` (cause set) |

---

## 6. Bundle & Tree-shaking Plan

### 6.1 Entry points (subpath exports)

> **Bundle-size headline: 10 KB is the CLIENT (`/browser`) target, not an overall number.**
> The research report's `target_bundle_size_kb: 10` reads as a single figure, but the server module legitimately needs ~10–14 KB (CBOR/COSE parsing, attestation verifier registry, JOSE for `SignedJwtChallengeStore`). A Worker bundle that imports `/server` will land at ~10 KB client + ~10–14 KB server. The README banner spells this out as `<10KB browser core, <15KB server core` — never as a single number — so the marketing claim is verifiable when someone runs `size-limit` on a Cloudflare Worker that uses the server module.

| Subpath                              | Purpose                  | Approx gzipped |
| ------------------------------------ | ------------------------ | -------------- |
| `@authkit/passkeys`                  | Types + version          | <0.5 KB        |
| `@authkit/passkeys/server`           | RP, verify, options      | ~10–14 KB (server budget) |
| `@authkit/passkeys/browser`          | startRegistration, startAuthentication | ~3–5 KB (counts toward 10KB client headline) |
| `@authkit/passkeys/types`            | Pure type re-exports     | 0 KB           |
| `@authkit/passkeys/errors`           | Error classes            | <1 KB          |
| `@authkit/passkeys/react`            | Hook + components        | ~2–3 KB        |
| `@authkit/passkeys/vue`              | Composable               | ~1–2 KB        |
| `@authkit/passkeys/sveltekit`        | Form actions             | ~1 KB          |
| `@authkit/passkeys/adapters/next`    | Next.js Route Handlers   | ~1 KB          |
| `@authkit/passkeys/adapters/hono`    | Hono sub-app             | ~1 KB          |
| `@authkit/passkeys/adapters/express` | Express Router           | ~1 KB          |
| `@authkit/passkeys/adapters/fastify` | Fastify plugin           | ~1 KB          |
| `@authkit/passkeys/adapters/nestjs`  | Module/Guard/Decorator   | ~1.5 KB        |
| `@authkit/passkeys/adapters/trpc`    | Procedure builder        | ~0.5 KB        |
| `@authkit/passkeys/storage/memory`   | In-memory adapter        | <0.5 KB        |
| `@authkit/passkeys/storage/prisma`   | Prisma adapter           | <0.5 KB        |
| `@authkit/passkeys/storage/drizzle`  | Drizzle adapter          | <0.5 KB        |
| `@authkit/passkeys/storage/kysely`   | Kysely adapter           | <0.5 KB        |
| `@authkit/passkeys/mds`              | MDS3 metadata client     | ~3–4 KB        |

### 6.2 Tree-shaking enablers

- `"sideEffects": false` in package.json.
- `verbatimModuleSyntax: true` + ESM-first build (no CJS interop magic in source).
- Each attestation format in its own file; `attestation-formats/index.ts` only re-exports — bundlers drop unused.
- No top-level `for ... of` over tables that touch every implementation.
- No `class Singleton` defaults at module load.
- All adapters in their own subpaths so importing `@authkit/passkeys/server` never reaches into `react/`, `nestjs/`, etc.

### 6.3 Build pipeline

- **`tsup`** (esbuild under the hood) emits ESM (`.js`) + CJS (`.cjs`) per entry, plus single-file `.d.ts` per entry via `dts: { resolve: true }`.
- Entries enumerated explicitly in `tsup.config.ts`; one file per entry → one chunk.
- `--treeshake` enabled; no shared chunk to avoid forcing imports across boundaries.
- Bundle-size guard in CI: `size-limit` with per-entry budgets matching the table above.

### 6.4 Conditional exports map (excerpt)

```jsonc
"exports": {
  ".":          { "types": "./dist/index.d.ts",          "import": "./dist/index.js",          "require": "./dist/index.cjs" },
  "./server":   {
    "types":       "./dist/server/index.d.ts",
    "workerd":     "./dist/server/index.edge.js",        // Cloudflare Workers — never reaches node-crypto-shim
    "edge-light":  "./dist/server/index.edge.js",        // Vercel Edge Runtime — same
    "deno":        "./dist/server/index.edge.js",
    "browser":     "./dist/server/index.edge.js",
    "import":      "./dist/server/index.js",             // Node — bundles node-crypto-shim.ts
    "require":     "./dist/server/index.cjs"
  },
  "./browser":  { "types": "./dist/browser/index.d.ts",  "browser": "./dist/browser/index.js", "import": "./dist/browser/index.js" }
  // … one per subpath
}
```

`server/node-crypto-shim.ts` does the only `import { webcrypto } from 'node:crypto'` in the codebase. It is the entry-point of `index.js` (Node default), and explicitly absent from `index.edge.js` — a static `import`, not a runtime `typeof process !== 'undefined'` guard, so esbuild/webpack/Wrangler/Workers all tree-shake the `node:crypto` reference cleanly. The order of conditions matters: `workerd` / `edge-light` MUST come before `import` so the Workers bundler picks the edge entry first.

The `"browser"` condition for `./browser` ensures bundlers without `node:` resolution prefer the browser build (identical to ESM but excluded from the CJS bundle to keep clients pure-ESM).

---

## 7. Dependencies

### 7.1 Runtime — zero direct dependencies (v0.1)

The core relies entirely on the platform: `crypto.subtle`, `crypto.getRandomValues`, `TextEncoder`/`TextDecoder`. Available in:

- Browser: all evergreen
- Node ≥ 18 (`globalThis.crypto`)
- Cloudflare Workers, Vercel Edge, Deno, Bun

Avoiding deps eliminates supply-chain surface and lets us beat SimpleWebAuthn on bundle size by 3–4×.

### 7.2 Why no `cbor` / `cbor-x` / `asn1js`

- We need **decode-only**, on a tiny subset of CBOR (COSE keys + attestation objects). A 1KB hand-written decoder is enough.
- Same for ASN.1: ECDSA-DER → raw r||s is ~30 lines.

### 7.3 Why no `@noble/hashes` / `@noble/curves`

- WebCrypto already provides `crypto.subtle.digest('SHA-256')` and `crypto.subtle.verify` for ES256/ES384/RS256/EdDSA on every supported runtime.
- Falling back to `@noble/*` would only help on hypothetical runtimes without WebCrypto — not a priority.
- We document this trade-off; if a community user needs `@noble/hashes` we can add a `pluggableCrypto` config (not v0.1).

### 7.4 Peer dependencies

Each adapter declares its host framework as an **optional peer**:

| Adapter            | Peer dependency               | Min version |
| ------------------ | ----------------------------- | ----------- |
| `react`            | `react`                       | `>=18`      |
| `vue`              | `vue`                         | `>=3.4`     |
| `sveltekit`        | `@sveltejs/kit`               | `>=2`       |
| `adapters/next`    | `next`                        | `>=14`      |
| `adapters/hono`    | `hono`                        | `>=4`       |
| `adapters/express` | `express`                     | `>=4`       |
| `adapters/fastify` | `fastify`                     | `>=4`       |
| `adapters/nestjs`  | `@nestjs/common`/`@nestjs/core` | `>=10`    |
| `adapters/trpc`    | `@trpc/server`                | `>=11`      |
| `storage/prisma`   | `@prisma/client`              | `>=5`       |
| `storage/drizzle`  | `drizzle-orm`                 | `>=0.30`    |
| `storage/kysely`   | `kysely`                      | `>=0.27`    |

All listed in `peerDependenciesMeta` with `optional: true` — installing the lib never forces them.

### 7.5 Dev dependencies (representative)

`typescript`, `tsup`, `vitest`, `@vitest/browser`, `@testing-library/react`, `happy-dom`, `eslint`, `@typescript-eslint/*`, `prettier`, `size-limit`, `@changesets/cli`, `playwright` (for E2E with virtual authenticator).

---

## 8. Configuration Files

### 8.1 `tsconfig.json`

```jsonc
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022", "DOM", "DOM.Iterable", "WebWorker"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "useUnknownInCatchVariables": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "esModuleInterop": false,
    "skipLibCheck": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "rootDir": "src",
    "resolveJsonModule": true,
    "jsx": "react-jsx"
  },
  "include": ["src/**/*"],
  "exclude": ["dist", "node_modules"]
}
```

### 8.2 `vitest.workspace.ts`

```ts
export default [
  { test: { name: 'node',    environment: 'node',       include: ['tests/{core,server,storage,mds,errors}/**/*.test.ts'] } },
  { test: { name: 'browser', environment: 'happy-dom',  include: ['tests/{browser,adapters/react,adapters/vue}/**/*.test.{ts,tsx}'] } },
  { test: { name: 'edge',    environment: 'edge-runtime', include: ['tests/edge/**/*.test.ts'] } },
];
```

Browser ceremony tests use a virtual authenticator via `@simplewebauthn/typescript-types` test fixtures — re-using community-curated real ceremony JSONs without depending on their runtime code.

### 8.3 `package.json` highlights

See the actual `package.json` checked in alongside this plan. Notable choices:

- `"type": "module"` — pure ESM source; tsup emits CJS shims.
- `"sideEffects": false` — every file is side-effect-free.
- `"engines.node": ">=18"` — first version with stable WebCrypto on global.
- `"exports"` — every entry has explicit `types`/`import`/`require` triplet.
- `"files": ["dist", "README.md", "LICENSE"]` — minimal published payload.
- `"publishConfig.provenance": true` — npm provenance attestations.

### 8.4 `tsup.config.ts` (sketch)

```ts
export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'server/index': 'src/server/index.ts',
    'browser/index': 'src/browser/index.ts',
    'types/index': 'src/types/index.ts',
    'errors/index': 'src/errors/index.ts',
    'mds/index': 'src/mds/index.ts',
    'react/index': 'src/adapters/react/index.ts',
    'vue/index': 'src/adapters/vue/index.ts',
    'sveltekit/index': 'src/adapters/sveltekit/index.ts',
    'adapters/next/index': 'src/adapters/next/index.ts',
    'adapters/hono/index': 'src/adapters/hono/index.ts',
    'adapters/express/index': 'src/adapters/express/index.ts',
    'adapters/fastify/index': 'src/adapters/fastify/index.ts',
    'adapters/nestjs/index': 'src/adapters/nestjs/index.ts',
    'adapters/trpc/index': 'src/adapters/trpc/index.ts',
    'storage/memory': 'src/storage/memory.ts',
    'storage/prisma': 'src/storage/prisma.ts',
    'storage/drizzle': 'src/storage/drizzle.ts',
    'storage/kysely': 'src/storage/kysely.ts',
  },
  format: ['esm', 'cjs'],
  target: 'es2022',
  splitting: false,
  treeshake: true,
  dts: { resolve: true },
  sourcemap: true,
  clean: true,
  outExtension: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
  define: { __PACKAGE_VERSION__: JSON.stringify(pkg.version) },
});
```

---

## 9. Edge Cases the Implementation MUST Handle

### 9.1 Encoding & parsing

- `clientDataJSON` containing the ` `–`` range — must NOT be re-stringified for hashing; hash the raw bytes the authenticator signed.
- Base64url with or without padding — accept both, emit unpadded.
- COSE map with negative integer keys — most COSE keys use them.
- CBOR map with non-canonical key ordering — accept any order.
- AAGUID rendered both as 16-byte buffer and as `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` UUID string.
- Empty AAGUID (`00000000-0000-0000-0000-000000000000`) for U2F-style credentials — never blanket-deny it; let policy decide.

### 9.2 Origin / RP-ID

- `rpId` may legitimately be a parent of `origin`'s host (subdomain registration). Validate via `endsWith('.' + rpId) || host === rpId`.
- Reject `localhost` only when `origin` scheme is `https:`; allow `http://localhost` for dev.
- Schemes other than `https:` and `http://localhost` MUST be rejected.
- Origins may be IPv6 literals — handle bracket-wrapped hosts.
- `origin` config accepts either string or array — multi-origin is common (apex + app subdomain).
- `rpId` MAY be omitted — default = effective domain of origin.

### 9.3 Sign-counter / replay

- Counter is `0` on the first authentication for many platform authenticators (iCloud/Google PM) — treat `0` specially: don't reject, but also don't increment as proof of non-replay.
- Authenticators that always return `0` are flagged in CredentialRecord (`signCountStatic`). The field starts as `null` (unknown) at registration time — the registration ceremony cannot distinguish "static" from "first-counter-happens-to-be-zero". `verifyAuthenticationResponse` flips it to `true` the first time it observes a 0-counter assertion (and to `false` the first time it sees a non-zero one); the caller persists the new value via `CredentialStore.update(...)` alongside `signCount`. Once `signCountStatic === true`, the "counter must increase" check is skipped for that credential.
- Sign counter MUST be compared as unsigned 32-bit integer.

### 9.4 Backup state

- `BE` (backup eligible) becomes `1` and never reverts to `0` over a credential's lifetime — verifying that BE didn't drop is required.
- `BS` (backup state) can flip both ways; use it to update CredentialRecord but don't reject mismatches.

### 9.5 User handle

- `user.id` MAY be up to 64 bytes of opaque binary. The public boundary accepts `Uint8Array` only (the previous `string | Uint8Array` form was lossy on non-UTF-8 binary IDs — see §4.1). For the common case of "I want to use my UUID-string user-id directly" the caller writes `new TextEncoder().encode(uuid)`; helpers in `core/encoding` (`utf8.encode`, `base64url.toBytes`) make this idiomatic. `CredentialRecord.userId` is also `Uint8Array`, so round-trip is byte-exact and free of UTF-8 decode bugs.
- Authentication response's `userHandle` MAY be null on non-discoverable flows — treat as a hint, not authoritative.

### 9.6 Discoverable credentials / passwordless

- `allowCredentials: []` triggers discoverable-credential flow. Server MUST then resolve the user from the response's `userHandle`, not from session/context.
- `userHandle` mismatch with `expectedUserId` (when caller supplies one) MUST be a hard failure.

### 9.7 Conditional UI

- `mediation: 'conditional'` requires an autocomplete="webauthn" input and an AbortController. Without it some browsers reject.
- The promise from a conditional-UI request can stay pending for the lifetime of the page — must be cancelable via signal.
- Calling `navigator.credentials.get` twice with conditional mediation in parallel must cancel the older one (handled internally by `usePasskey`).

### 9.8 Browser quirks

- Safari refuses `attestation: 'direct'` for platform authenticators — default to `'none'` and document the option.
- Windows Hello uses AAGUIDs that vary across builds; surface AAGUID transparently rather than hard-coding allow-lists.
- Android sync provider may rotate AAGUIDs across Play Services updates — caching MDS lookups requires TTL.
- Some browsers expose `parseCreationOptionsFromJSON` only behind a flag — feature detect.

### 9.9 Cross-runtime

- Cloudflare Workers exposes `crypto.subtle` but not `Buffer`. All encoding must be Uint8Array-based.
- Node 18 didn't expose `globalThis.crypto` everywhere — `server/node-crypto-shim.ts` does the only `import { webcrypto } from 'node:crypto'` in the codebase. It is reachable ONLY through the `import` (Node) export condition; `workerd` / `edge-light` / `deno` / `browser` conditions resolve to a separate `index.edge.js` entry that has no path to the shim. This is a static-import boundary — not a runtime `typeof process !== 'undefined'` guard, which esbuild would still bundle and Workers would still reject. See §6.4 for the exports map.
- Edge runtime forbids dynamic `eval`/`Function`; we never use them.

### 9.10 Timing & abuse

- Challenge tokens are single-use and short-TTL (default 5 min). Replay of challengeToken MUST fail.
- All `verifySignature` paths MUST pass through WebCrypto's constant-time-ish primitives; never compare buffers with `==`.
- Public `findById` lookup must not leak credentialId enumeration via timing or error shape. Concretely: when the credentialId is unknown, we still perform a dummy `crypto.subtle.verify` against a placeholder key (matching the shape of a real verify call) before returning. The returned `error.code` is the aggregate `'authentication-failed'` (§4.1), with `details.reason: 'unknown-credential' | 'bad-signature'` available **only** to server-side audit logs. Callers MUST NOT branch UX on `details.reason` — the §2.7 example shows the correct pattern.

### 9.11 Storage

- `excludeCredentials` SHOULD include all of a user's credentials, otherwise the user can register the same authenticator twice. Caller responsibility, but `RelyingParty.startRegistration` will auto-fetch from `credentialStore.findByUserId` if not supplied.
- `delete()` of a credential during an in-flight auth ceremony — return `unknown-credential`, don't crash.
- Prisma/Drizzle adapters use upsert with credentialId as PK — collisions throw `PasskeyVerificationError('invalid-state')`.

### 9.12 PRF / largeBlob extensions

- PRF results are ArrayBuffers that may be empty — wrap in null-safe accessors.
- `largeBlob` writes can silently fail; surface `clientExtensionResults.largeBlob.written === false` as a non-fatal warning to caller.

### 9.13 Account portability (iOS 26 export)

- An imported credential keeps its `credentialId` but may surface a new AAGUID. `findById` is still the key; AAGUID change is recorded but not a verification failure.

---

## 10. Security Posture (cross-cutting)

- Every public method has a documented threat model in JSDoc.
- We never log raw `clientDataJSON` or signatures (only digests + length + alg).
- `RelyingParty` defaults to `userVerification: 'required'`. Rationale: the research report's primary personas are fintech / healthcare with NIST AAL3 and PSD2 SCA compliance requirements, where a default that silently drops UV would be a silent compliance bug. Consumer-grade flows opt down to `'preferred'` with one line.
- `attestation: 'none'` is default — `direct`/`enterprise` requires explicit opt-in and an MDS3 client to be useful.
- All challenge bytes come from `crypto.getRandomValues`; never `Math.random`.
- `SignedJwtChallengeStore` supports kid-based key rotation out of the box (§2.6) so secret rotation never orphans in-flight registrations.
- `finishAuthentication` collapses `unknown-credential` and `bad-signature` into a single public `'authentication-failed'` code so an attacker cannot enumerate credentialIds via error-shape or response-time difference (see §9.10). Internal granularity stays in `error.details.reason` for server logs only.
- Documentation includes a "RP-ID confusion in multi-tenant deployments" appendix — the most common security mistake.

---

## 11. Versioning & Stability

- v0.x — semver-minor for breaking changes, semver-patch for fixes.
- v1.0 commits the public API surface enumerated in §2 + the error-code list in §5.3.
- **v1.0 stability commitments** (changing any of these is a major version bump):
  - Default `userVerification: 'required'`. Flipping the default is a breaking change for the AAL3/SCA audience.
  - `RelyingParty` is the only public server entry. Re-introducing standalone `generate*/verify*` functions would re-fragment the surface.
  - `'authentication-failed'` and `'registration-failed'` are aggregate codes; their `details.reason` strings are explicitly NOT part of the public contract and may change between minor versions.
- Browser feature support tracks WebAuthn Level 2 Recommendation as the floor; Level 3 features marked experimental in JSDoc until ratified.

---

## 12. Out-of-scope (v0.1, mirrors research report)

- Full session management (lives in `@authkit/session`).
- UI library beyond minimal `<PasskeyButton />` and `<PasskeyInput />` (Hanko Elements territory).
- Email/SMS/OTP factors.
- FIDO U2F legacy flows.
- Hosted SaaS / cloud credential storage.
- Full TPM and Android-Key attestation verification (stubs return `unsupported-attestation-format`; documented roadmap for v0.3).

---

## Review Changes

Responses to Vasyl Bruhanda's PR #1 review (REQUEST_CHANGES verdict). Each row lists the original concern, my response, and which sections of PLAN.md / package.json were touched.

### BLOCKER #1 — Inconsistent `userVerification` default (§10 vs §2.1 example)
- **Concern:** §10 said default `'preferred'`, but the §2.1 worked example used `'required'`. For fintech / healthcare audiences (NIST AAL3, PSD2 SCA) a default that drops UV is a silent compliance bug.
- **Response (AGREE):** Aligned both to `'required'` as the default. Documented `'preferred'` as the consumer-grade opt-down.
- **Sections changed:** §2.1 (config example comment), §10 (security posture rationale), §11 (added v1.0 stability commitment that flipping the default is a major bump).

### BLOCKER #2 — Timing/error-shape leak (§9.10 vs §4.1 vs §2.7)
- **Concern:** §9.10 mandated indistinguishable error paths for `unknown-credential` and `bad-signature`, but §4.1 listed them as distinct public codes and §2.7 actively encouraged switching on them.
- **Response (AGREE):** Collapsed both into a single public-boundary code `'authentication-failed'` (and `'registration-failed'` for the registration-side equivalent). The granular reason now lives ONLY on `error.details.reason`, documented as server-internal and explicitly NOT part of the public contract. Added a constant-time-shape dummy verify on the unknown-credential path so response time matches.
- **Sections changed:** §2.7 (rewritten example with explicit "never forward .details to client"), §4.1 (added new aggregate codes; introduced `PasskeyInternalReason` type for server-only audit strings), §9.10 (rewrote to describe the dummy-verify pattern and reference §2.7), §10 (added explicit security-posture bullet), §11 (added v1.0 stability commitment that `details.reason` is unstable).

### HIGH #3 — DOM-typed `extensions?: AuthenticationExtensionsClientInputs` on server boundary
- **Concern:** `AuthenticationExtensionsClientInputs` is a `lib.dom.d.ts` type; leaking it into a server-only public API contradicts the §9.9 "no DOM-in-Node footgun" promise.
- **Response (AGREE):** Replaced with a library-owned `PasskeyExtensionsInput` defined in `types/webauthn-json.ts`. Marked the same audit for `clientExtensionResults` in §1's file-tree comment.
- **Sections changed:** §1 (`types/webauthn-json.ts` comment expanded), §2.1 (`StartRegistrationInput.extensions` type swapped).

### HIGH #4 — Public-API surface too wide (RP class + standalone fns + adapters = 3 entry points)
- **Concern:** Three ways to do registration triples the docs/test/bug surface for a multi-tenant use case the standalone form was justifying.
- **Response (AGREE):** Removed the standalone `generateRegistrationOptions` / `verifyRegistrationResponse` / `generateAuthenticationOptions` / `verifyAuthenticationResponse` exports. Multi-tenant / per-request config now flows through a new `resolveConfig: (ctx) => Promise<Partial<RpConfig>>` callback on `RelyingParty`. The internal helper files still exist (renamed to `_buildRegistrationOptions` etc.) but are no longer re-exported from `server/index.ts`.
- **Sections changed:** §1 (file-tree comments mark `options-*.ts` / `verify-*.ts` as INTERNAL), §2.1 (added multi-tenant `resolveConfig` example, replaced "Standalone function form" subsection with an explicit "single entry point" note), §3.4 (replaced "Dual API" pattern with "Single public entry point per layer"), §11 (v1.0 commitment).

### HIGH #5 — `signCountStatic` referenced in §9.3 but missing from `CredentialRecord`
- **Concern:** §9.3 said the field should exist; §2.1 didn't have it.
- **Response (AGREE):** Added `signCountStatic: boolean | null` to `CredentialRecord`. Documented that it starts `null` (registration can't tell), and that `verifyAuthenticationResponse` flips it on the first authentication. Caller persists via `CredentialStore.update(...)` alongside `signCount`.
- **Sections changed:** §2.1 (CredentialRecord shape + JSDoc), §9.3 (extended explanation of the lifecycle).

### HIGH #6 — Missing first-class `onFallback` (research-report differentiator)
- **Concern:** Fallback strategies surfaced only as a JSX `fallback` prop; no callable hook on `usePasskey`, none on the non-React adapters.
- **Response (AGREE):** Added `onFallback?: (reason: PasskeyErrorCode) => void` to `UsePasskeyOptions`. Added a 'fallback' state. Documented the same callback shape on Hono/Next/Express adapter handler config so the contract is uniform across frameworks.
- **Sections changed:** §2.3 (login example, hook signature, `UsePasskeyOptions`, new "Non-React adapters" subsection).

### MEDIUM #7 — Bundle-size headline ambiguity (10KB total vs 10KB client)
- **Concern:** README banner suggested a single 10KB number while §6.1 budgets server at 10–14KB; a Worker bundle that imports `/server` will visibly exceed 10KB.
- **Response (AGREE):** Top-of-document banner now reads "<10KB browser core, <15KB server core" and never as a single number. §6.1 leads with an explicit "10 KB is the CLIENT target, not an overall number" callout that pre-empts the marketing-claim challenge.
- **Sections changed:** Top banner, §6.1 (new explanatory paragraph + table cell labels).

### MEDIUM #8 — Browser exports `register` / `authenticate` clash with common names
- **Concern:** Generic names collide with React conventions, lit-element, OAuth, and IDE auto-import.
- **Response (AGREE):** Renamed to `startRegistration` / `startAuthentication`. Bonus benefit: now mirrors the server `RelyingParty.startRegistration` / `.startAuthentication` method names so a developer reading both halves of the ceremony reads the same verb.
- **Sections changed:** §1 (`browser/start-registration.ts` / `start-authentication.ts` filenames updated), top banner (mention of new names), §2.2 (heading, example, JSDoc, function signatures all renamed; added rationale paragraph).

### MEDIUM #9 — `SignedJwtChallengeStore` lacks key-rotation contract
- **Concern:** No `kid` header / multi-key support; rotating the secret orphans every in-flight registration.
- **Response (AGREE):** Constructor now takes `keys: Array<{kid, secret}>` with verify-any / sign-newest semantics. Single-key form retained as a normalize-to-array convenience.
- **Sections changed:** §1 (`server/challenge.ts` comment), §2.6 (full rotation example + `kid`-header description), §3.4 (mention rotation in the "Pluggable stores" bullet), §10 (security-posture bullet).

### MEDIUM #10 — Edge-runtime `node:crypto` resolution path unspecified
- **Concern:** The plan said we'd polyfill `import { webcrypto }` "only inside Node-conditional code paths" but didn't say HOW; runtime guards still get bundled.
- **Response (AGREE):** Added explicit `workerd` / `edge-light` / `deno` / `browser` conditions to the `./server` (and edge-deployed adapter) exports map, resolving to a separate `index.edge.js` entry that has no static path to the new `server/node-crypto-shim.ts`. The shim is the single point that does the Node-only import. Documented that this is a static-import boundary, not a runtime guard.
- **Sections changed:** §1 (added `server/node-crypto-shim.ts`), §6.4 (rewritten exports-map example with explicit condition order + rationale), §9.9 (replaced the vague "we polyfill" line with a concrete description), `package.json` (`./server`, `./adapters/next`, `./adapters/hono` exports map).

### MEDIUM #11 — `Partial<AuthenticatorPolicy>` accepts unknown keys
- **Concern:** Under `exactOptionalPropertyTypes`, a typo'd field on a `Partial<>` becomes a silent no-op.
- **Response (AGREE):** Defined an explicit `AuthenticatorPolicyOverride` interface (per-field optional, no index signature) and used it on both `StartRegistrationInput.policy` and `FinishRegistrationInput.policy`. Added a runtime `assertKnownPolicyKeys` boundary check for plain-JS callers without TS strict mode.
- **Sections changed:** §1 (`types/policy.ts` and `server/policies.ts` comments), §2.1 (input types), §4.5 (added new bullet with the explicit interface).

### LOW #12 — `expectedUserId: string | Uint8Array` causes lossy UTF-8 decode bug
- **Concern:** Accepting both at the boundary forces a round-trip that loses bytes for non-UTF-8 binary user IDs; `CredentialRecord.userId: string` is a bug surface.
- **Response (AGREE):** Tightened the boundary to `Uint8Array` only. `CredentialRecord.userId` is now `Uint8Array` too. Callers with UUID strings write `new TextEncoder().encode(uuid)`; helpers in `core/encoding` make this idiomatic. Documented the rationale in §9.5.
- **Sections changed:** §2.1 (`StartRegistrationInput.user.id` type, `FinishRegistrationInput.expectedUserId`, `CredentialRecord.userId`), §9.5 (rewrote the "User handle" item to explain the boundary).

### LOW #13 — `errors/` import-rule exception not spelled out
- **Concern:** `errors/` is shown imported by every layer in the diagram, but the ESLint `no-restricted-imports` rule didn't list it as an exception.
- **Response (AGREE):** Added an explicit "errors/ is the only module every layer is allowed to depend on" line at the top of the §3.1 hard-rules list, plus an inline note on the `core/*` rule.
- **Sections changed:** §3.1 (rules block).

### NIT #14 — Default transports list is missing `'nfc'` and `'ble'`
- **Concern:** Hybrid/QR cross-device flow is a key UX in the report.
- **Response (AGREE):** Default transports list now includes all five spec values: `['internal', 'hybrid', 'usb', 'nfc', 'ble']`.
- **Sections changed:** §2.1 (RelyingParty config example).

### Files modified
- `PLAN.md` — sections §1, §2.1, §2.2, §2.3, §2.6, §2.7, §3.1, §3.4, §4.1, §4.5, §6.1, §6.4, §9.3, §9.5, §9.9, §9.10, §10, §11, top banner, this new "Review Changes" section.
- `package.json` — `exports["./server"]`, `exports["./adapters/next"]`, `exports["./adapters/hono"]` extended with `workerd` / `edge-light` / `deno` / `browser` conditions resolving to `*.edge.js` entries.
