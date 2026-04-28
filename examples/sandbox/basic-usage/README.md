# Basic usage — `@authkit/passkeys`

Minimal end-to-end ceremony: register a passkey, then log in with it. The
browser-side `navigator.credentials.*` calls are stood in for by an in-process
software authenticator (`_simulator.ts`) so the example is fully runnable in
Node — every server-side call (`generateRegistrationOptions`,
`verifyRegistration`, `verifyAuthentication`) executes against the real
library code.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/basic-usage)

## Run locally

```bash
npm install
npm start
```

## What's wired up

| Step | Server call | Notes |
| --- | --- | --- |
| 1 | `generateRegistrationOptions` | Mints challenge + signed envelope (HMAC, kid-aware). |
| 2 | `simulateRegistration`        | Stand-in for `startRegistration` in the browser. |
| 3 | `verifyRegistration`          | Validates attestation, returns `NewCredentialRecord`. |
| 4 | `generateAuthenticationOptions` | Discoverable / passkey-first flow (no `allowCredentials`). |
| 5 | `simulateAuthentication`      | Stand-in for `startAuthentication`. |
| 6 | `verifyAuthentication`        | Validates assertion, returns the typed `userId`. |
