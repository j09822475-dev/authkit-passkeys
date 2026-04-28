# `@authkit/passkeys` — Architecture Plan

> Lightweight, framework-agnostic Passkey/WebAuthn library targeting Browser + Node + Edge.
> Targets <10KB gzipped client core, <15KB server core. WebAuthn Level 3 first, no `cbor`/`asn1js`/`@hexagon/base64`.
>
> Differentiation vs `@simplewebauthn`: opinionated user-flow API (one `register()` / `authenticate()` instead of six functions), zero `node:crypto` (pure WebCrypto), custom 1KB COSE-key parser, framework adapters in the box.

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
│   │   ├── index.ts                  # Public exports: RelyingParty, generate*, verify*
│   │   ├── relying-party.ts          # RelyingParty class — central config + methods
│   │   ├── options-registration.ts   # generateRegistrationOptions()
│   │   ├── options-authentication.ts # generateAuthenticationOptions()
│   │   ├── verify-registration.ts    # verifyRegistrationResponse()
│   │   ├── verify-authentication.ts  # verifyAuthenticationResponse()
│   │   ├── challenge.ts              # ChallengeStore interface + InMemoryChallengeStore + helpers
│   │   ├── credential-store.ts       # CredentialStore interface — user-supplied
│   │   ├── policies.ts               # AuthenticatorPolicy (AAGUID allow/deny, transport, UV required, etc.)
│   │   ├── audit.ts                  # AuditHook type + emitAudit() helper
│   │   └── defaults.ts               # Sensible RP defaults (timeout, AS, attestation:'none', etc.)
│   │
│   ├── browser/                      # Client (user agent) API — runs only in browser
│   │   ├── index.ts                  # Public exports
│   │   ├── register.ts               # register(serverOptions, opts?) — full ceremony wrapper
│   │   ├── authenticate.ts           # authenticate(serverOptions, opts?) — incl. conditional mediation
│   │   ├── feature-detect.ts         # isPasskeySupported / isConditionalUISupported / isPlatformAuthenticatorAvailable
│   │   ├── parse-options.ts          # parseCreationOptionsFromJSON / parseRequestOptionsFromJSON
│   │   │                              # (uses native if present, falls back to manual base64url decode)
│   │   ├── serialize-response.ts     # toJSON() polyfill for PublicKeyCredential when needed
│   │   ├── abort.ts                  # AbortController helpers — esp. for canceling conditional mediation
│   │   └── prf.ts                    # WebAuthn PRF extension helpers (Level 3)
│   │
│   ├── types/                        # All public types live here for explicit import path
│   │   ├── index.ts                  # Barrel — used by `@authkit/passkeys/types`
│   │   ├── webauthn-json.ts          # CredentialCreationOptionsJSON, CredentialRequestOptionsJSON, etc.
│   │   ├── ceremony.ts               # ParsedAttestation, ParsedAssertion, AuthenticatorData
│   │   ├── credential.ts             # CredentialRecord, StoredPublicKey, BackupState
│   │   ├── policy.ts                 # AuthenticatorPolicy, RpConfig
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
    userVerification: 'required',
    residentKey: 'preferred',
    authenticatorAttachment: undefined,       // any
    aaguidAllowList: undefined,
    transports: ['internal', 'hybrid', 'usb'],
  },
  audit: (event) => logger.info(event),
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

#### Standalone function form (no RP class)

For users who want functional style or have heterogeneous RPs per request:

```ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@authkit/passkeys/server';

const options = await generateRegistrationOptions({
  rpName, rpId, origin, user, challengeStore, policy,
});

const result = await verifyRegistrationResponse({
  response, expectedChallenge, expectedOrigin, expectedRpId, policy,
});
```

#### `StartRegistrationInput` / `Output`

```ts
export interface StartRegistrationInput {
  user: { id: string | Uint8Array; name: string; displayName: string };
  excludeCredentials?: Array<{ id: string; transports?: AuthenticatorTransport[] }>;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
  policy?: Partial<AuthenticatorPolicy>;       // overrides RP defaults for this ceremony
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
  expectedUserId: string | Uint8Array;
  /** Override RP-level policy for this single verification. */
  policy?: Partial<AuthenticatorPolicy>;
}

/** What the caller persists. CredentialStore.save(record) */
export interface CredentialRecord {
  credentialId: string;                    // base64url
  userId: string;                          // mirrors RP user.id
  publicKey: Uint8Array;                   // SPKI-encoded; passkey can re-import via WebCrypto
  publicKeyAlgorithm: COSEAlgorithmIdentifier;
  signCount: number;
  transports: AuthenticatorTransport[];
  aaguid: string;                          // hex-formatted UUID
  backupEligible: boolean;
  backupState: boolean;
  attestationFormat: string;
  createdAt: Date;
}
```

### 2.2 Browser — `register` / `authenticate`

```ts
import { register, authenticate, isPasskeySupported } from '@authkit/passkeys/browser';

if (!isPasskeySupported()) {
  // graceful fallback
}

// 1. Fetch options from server (returns startRegistration output)
const { options, challengeToken } = await fetch('/api/passkey/start-registration')
  .then((r) => r.json());

// 2. Run ceremony
const credential = await register(options, {
  signal: abortController.signal,
});

// 3. POST credential back, server.finishRegistration verifies
await fetch('/api/passkey/finish-registration', {
  method: 'POST',
  body: JSON.stringify({ challengeToken, response: credential }),
});
```

#### `register`

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
 * @param opts.useAutofill      Currently registration-irrelevant; reserved.
 * @returns          RegistrationResponseJSON ready to POST back to server.
 * @throws PasskeyClientError   With one of: 'not-supported', 'user-cancelled',
 *                              'invalid-state' (already registered), 'security-error',
 *                              'timeout', 'unknown'.
 */
export function register(
  options: PublicKeyCredentialCreationOptionsJSON | PublicKeyCredentialCreationOptions,
  opts?: { signal?: AbortSignal },
): Promise<RegistrationResponseJSON>;
```

#### `authenticate`

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
export function authenticate(
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
 * State: 'idle' | 'starting' | 'awaiting-user' | 'verifying' | 'success' | 'error'
 *
 * - Uses startUrl/finishUrl convention by default; override fetcher for custom transport.
 * - Auto-cancels in-flight conditional-UI request on unmount.
 */
export function usePasskey<TSuccess = unknown>(opts: UsePasskeyOptions<TSuccess>): {
  state: PasskeyState;
  error: PasskeyError | null;
  register: () => Promise<TSuccess>;
  authenticate: (opts?: { useAutofill?: boolean }) => Promise<TSuccess>;
  reset: () => void;
};
```

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

Default implementations: `InMemoryChallengeStore` (testing), `SignedJwtChallengeStore` (stateless — HS256 over a server secret, no DB round-trip).

### 2.7 Errors as values

Every public method that performs verification returns `Result<T, PasskeyError>` instead of throwing. Programmer errors (missing config, wrong types) throw `PasskeyInternalError` synchronously.

```ts
const result = await rp.finishAuthentication(input);
if (!result.ok) {
  switch (result.error.code) {
    case 'bad-challenge':       // challenge expired or never issued
    case 'bad-origin':
    case 'bad-rp-id':
    case 'bad-signature':
    case 'replay-detected':     // sign-counter went backwards
    case 'unknown-credential':
    case 'aaguid-not-allowed':
    case 'user-verification-required':
      return reject(result.error);
  }
}
return accept(result.value);
```

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

- `core/*` MUST NOT import from `server/`, `browser/`, `adapters/`, `storage/`, `mds/`.
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
- **Pluggable stores** — `ChallengeStore` and `CredentialStore` are injected. Default in-memory + signed-JWT shipped.
- **Strategy pattern for attestation formats** — `attestation-formats/` exports a registry; `RelyingParty` accepts a custom registry to add/replace verifiers. Unused formats tree-shake out.
- **Dual API: class + standalone fns** — `RelyingParty` for typical app code, standalone fns for multi-tenant / per-request RP scenarios.
- **Adapter pattern** — framework adapters wrap the core lib without coupling it to any framework.
- **Tagged unions everywhere** — `Result`, error codes, ceremony states are all discriminated unions to maximize TS narrowing.

---

## 4. Type System

### 4.1 Core primitives

```ts
// errors/codes.ts
export type PasskeyErrorCode =
  | 'not-supported'
  | 'user-cancelled'
  | 'invalid-state'
  | 'security-error'
  | 'timeout'
  | 'bad-challenge'
  | 'bad-origin'
  | 'bad-rp-id'
  | 'bad-signature'
  | 'replay-detected'
  | 'unknown-credential'
  | 'aaguid-not-allowed'
  | 'user-verification-required'
  | 'transport-not-allowed'
  | 'unsupported-attestation-format'
  | 'malformed-response'
  | 'unknown';

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

| Subpath                              | Purpose                  | Approx gzipped |
| ------------------------------------ | ------------------------ | -------------- |
| `@authkit/passkeys`                  | Types + version          | <0.5 KB        |
| `@authkit/passkeys/server`           | RP, verify, options      | ~10–14 KB      |
| `@authkit/passkeys/browser`          | register, authenticate   | ~3–5 KB        |
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
  "./server":   { "types": "./dist/server/index.d.ts",   "import": "./dist/server/index.js",   "require": "./dist/server/index.cjs" },
  "./browser":  { "types": "./dist/browser/index.d.ts",  "browser": "./dist/browser/index.js", "import": "./dist/browser/index.js" }
  // … one per subpath
}
```

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
- Authenticators that always return `0` should be flagged in CredentialRecord (`signCountStatic = true`) so policy can decide.
- Sign counter MUST be compared as unsigned 32-bit integer.

### 9.4 Backup state

- `BE` (backup eligible) becomes `1` and never reverts to `0` over a credential's lifetime — verifying that BE didn't drop is required.
- `BS` (backup state) can flip both ways; use it to update CredentialRecord but don't reject mismatches.

### 9.5 User handle

- `user.id` MAY be up to 64 bytes of opaque binary. We accept both string (UTF-8 decoded) and Uint8Array; round-trip preserves bytes.
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
- Node 18 didn't expose `globalThis.crypto` everywhere — we polyfill via `import { webcrypto }` only inside Node-conditional code paths.
- Edge runtime forbids dynamic `eval`/`Function`; we never use them.

### 9.10 Timing & abuse

- Challenge tokens are single-use and short-TTL (default 5 min). Replay of challengeToken MUST fail.
- All `verifySignature` paths MUST pass through WebCrypto's constant-time-ish primitives; never compare buffers with `==`.
- Public `findById` lookup must not leak credentialId enumeration via timing — error path for `unknown-credential` should be the same shape as `bad-signature`.

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
- `RelyingParty` defaults to `userVerification: 'preferred'` (UX) but `userVerification: 'required'` is one-line opt-in and recommended in docs for sensitive flows.
- `attestation: 'none'` is default — `direct`/`enterprise` requires explicit opt-in and an MDS3 client to be useful.
- All challenge bytes come from `crypto.getRandomValues`; never `Math.random`.
- Documentation includes a "RP-ID confusion in multi-tenant deployments" appendix — the most common security mistake.

---

## 11. Versioning & Stability

- v0.x — semver-minor for breaking changes, semver-patch for fixes.
- v1.0 commits the public API surface enumerated in §2 + the error-code list in §5.3.
- Browser feature support tracks WebAuthn Level 2 Recommendation as the floor; Level 3 features marked experimental in JSDoc until ratified.

---

## 12. Out-of-scope (v0.1, mirrors research report)

- Full session management (lives in `@authkit/session`).
- UI library beyond minimal `<PasskeyButton />` and `<PasskeyInput />` (Hanko Elements territory).
- Email/SMS/OTP factors.
- FIDO U2F legacy flows.
- Hosted SaaS / cloud credential storage.
- Full TPM and Android-Key attestation verification (stubs return `unsupported-attestation-format`; documented roadmap for v0.3).
