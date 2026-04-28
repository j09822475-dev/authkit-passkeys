# Hono integration — `@authkit/passkeys`

The same Hono app boots unchanged on Cloudflare Workers, Vercel Edge,
Deno Deploy, Bun, and Node. Wires the four ceremony endpoints behind
cookie-bound challenge tokens, then exercises them end-to-end via
`app.request()` — actual HTTP traffic, no listener required.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/j09822475-dev/authkit-passkeys/tree/main/examples/sandbox/with-hono)

## Run locally

```bash
npm install
npm start
```

## Endpoints

| Verb | Path | Server call |
| --- | --- | --- |
| POST | `/api/passkey/register/options` | `generateRegistrationOptions` |
| POST | `/api/passkey/register/verify`  | `verifyRegistration` + `store.create` |
| POST | `/api/passkey/login/options`    | `generateAuthenticationOptions` |
| POST | `/api/passkey/login/verify`     | `verifyAuthentication` + `store.updateCounter` |

The `Set-Cookie` carries the signed challenge envelope (HMAC HS256, 5-minute
TTL) — the verifier reads it back from `Cookie:` on the matching `/verify`
call. Swap the simulated authenticator for `startRegistration` /
`startAuthentication` from `@authkit/passkeys/browser` when wiring this into
a real frontend.
