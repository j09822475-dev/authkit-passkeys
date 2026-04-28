/**
 * Hono integration — same code runs unchanged on Cloudflare Workers,
 * Vercel Edge, Deno Deploy, Bun, and Node.
 *
 * Wires the four ceremony endpoints behind cookie-bound challenge tokens:
 *
 *   POST /api/passkey/register/options
 *   POST /api/passkey/register/verify
 *   POST /api/passkey/login/options
 *   POST /api/passkey/login/verify
 *
 * Then exercises them end-to-end via `app.request()` — the same HTTP traffic
 * a real client would generate, no listener required. Swap the simulated
 * authenticator for `startRegistration` / `startAuthentication` from
 * `@authkit/passkeys/browser` when wiring this into a real frontend.
 *
 * Run:  npx tsx examples/with-hono.ts
 */

import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie';

import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistration,
  verifyAuthentication,
} from '@authkit/passkeys/server';
import { createMemoryCredentialStore } from '@authkit/passkeys/storage/memory';
import { isPasskeyError } from '@authkit/passkeys/errors';
import type { ChallengeSigningKeys } from '@authkit/passkeys/types';

import {
  createVirtualAuthenticator,
  simulateAuthentication,
  simulateRegistration,
} from './_simulator.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';
const COOKIE_REG = 'passkey_reg';
const COOKIE_AUTH = 'passkey_auth';

const signingKeys: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'replace-me-with-a-32-byte-random-secret' },
};

// Module-scope user/store so the example fits in one file. In production this
// is your DB-backed implementation of `CredentialStore`.
const store = createMemoryCredentialStore();
const DEMO_USER = { id: 'user_alice', name: 'alice@example.com', displayName: 'Alice' };

const app = new Hono();

app.post('/api/passkey/register/options', async (c) => {
  const { options, challengeToken } = await generateRegistrationOptions({
    rp: { id: RP_ID, name: 'Example' },
    user: DEMO_USER,
    store,
    signingKeys,
  });
  setCookie(c, COOKIE_REG, challengeToken, {
    httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 300, path: '/',
  });
  return c.json(options);
});

app.post('/api/passkey/register/verify', async (c) => {
  const challengeToken = getCookie(c, COOKIE_REG);
  if (!challengeToken) return c.json({ error: 'missing challenge cookie' }, 400);
  try {
    const newRecord = await verifyRegistration({
      response: await c.req.json(),
      challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      signingKeys,
    });
    await store.create({ ...newRecord, userId: DEMO_USER.id });
    return c.json({ ok: true, credentialId: newRecord.credentialId });
  } catch (err) {
    if (isPasskeyError(err)) return c.json(err.toJSON(), 400);
    throw err;
  }
});

app.post('/api/passkey/login/options', async (c) => {
  const { options, challengeToken } = await generateAuthenticationOptions({
    rp: { id: RP_ID }, store, signingKeys,
  });
  setCookie(c, COOKIE_AUTH, challengeToken, {
    httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 300, path: '/',
  });
  return c.json(options);
});

app.post('/api/passkey/login/verify', async (c) => {
  const challengeToken = getCookie(c, COOKIE_AUTH);
  if (!challengeToken) return c.json({ error: 'missing challenge cookie' }, 400);
  try {
    const verified = await verifyAuthentication({
      response: await c.req.json(),
      challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      store,
      signingKeys,
    });
    await store.updateCounter(verified.credential.credentialId, verified.newCounter);
    return c.json({ userId: verified.userId, userVerified: verified.userVerified });
  } catch (err) {
    if (isPasskeyError(err)) return c.json(err.toJSON(), 401);
    throw err;
  }
});

// ---- Drive the app via app.request() — real HTTP, no listener ------------

async function main(): Promise<void> {
  const authenticator = await createVirtualAuthenticator({ origin: ORIGIN, rpId: RP_ID });

  // Cookie jar (single-flight: copy whatever the server sets).
  let cookies = '';
  const captureCookie = (res: Response): void => {
    const setCookieHeader = res.headers.get('set-cookie');
    if (setCookieHeader) cookies = setCookieHeader.split(';')[0]!;
  };

  console.log('POST /api/passkey/register/options');
  const regOptionsRes = await app.request('/api/passkey/register/options', { method: 'POST' });
  captureCookie(regOptionsRes);
  const regOptions = await regOptionsRes.json();
  console.log('   challenge =', regOptions.challenge);

  const regResponse = await simulateRegistration(authenticator, regOptions);

  console.log('POST /api/passkey/register/verify');
  const regVerifyRes = await app.request('/api/passkey/register/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookies },
    body: JSON.stringify(regResponse),
  });
  console.log('   status =', regVerifyRes.status, '/ body =', await regVerifyRes.json());

  console.log('POST /api/passkey/login/options');
  const loginOptionsRes = await app.request('/api/passkey/login/options', { method: 'POST' });
  captureCookie(loginOptionsRes);
  const loginOptions = await loginOptionsRes.json();
  console.log('   challenge =', loginOptions.challenge);

  const authResponse = await simulateAuthentication(authenticator, loginOptions);

  console.log('POST /api/passkey/login/verify');
  const loginVerifyRes = await app.request('/api/passkey/login/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookies },
    body: JSON.stringify(authResponse),
  });
  console.log('   status =', loginVerifyRes.status, '/ body =', await loginVerifyRes.json());

  console.log('\nDone — Hono app served the full ceremony.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
