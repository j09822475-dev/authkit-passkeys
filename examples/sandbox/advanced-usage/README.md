# Advanced usage — `@authkit/passkeys`

Production-shaped scenario: branded `UserId`, in-flight signing-key rotation,
AAGUID allowlist, audit hooks, sign-counter regression detection, and the
single-public-`authentication_failed` enumeration-oracle defence.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/advanced-usage)

## Run locally

```bash
npm install
npm start
```

## What's wired up

1. **Branded `UserId`.** `CredentialStore<UserId>` propagates the brand through every server call — `verifyAuthentication` returns `userId: UserId`, never `string`.
2. **Signing-key rotation.** Tokens minted under `kid=k1` continue to verify after the deploy flips to `kid=k2` because `k1` is kept in `previous`.
3. **AAGUID allowlist.** Only the Apple platform AAGUID and YubiKey 5C are accepted; anonymous / `'none'`-attestation registrations are explicitly opted in via `allowAnonymous: true`.
4. **Audit hooks.** `onVerified` records the BS-bit flip when a single-device credential gets backed up to multi-device sync (e.g. iCloud Keychain).
5. **Counter-regression guard.** A rewound sign-counter surfaces as `CounterRegressionError`.
6. **Enumeration-oracle defence.** An unknown credential ID surfaces as `AuthenticationFailedError(code: 'authentication_failed')` — the granular `details.reason` (`'unknown_credential'`) stays on the error object for server logs and is stripped by `toJSON()` so it never reaches the wire.
