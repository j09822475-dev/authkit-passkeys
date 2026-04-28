/**
 * Advanced real-world passkey scenario.
 *
 * Threads together the production-shaped knobs the README and PLAN spell out:
 *
 *   • Branded `UserId` carried end-to-end through `CredentialStore<UserId>`.
 *   • `signingKeys.previous` covering an in-flight key rotation.
 *   • AAGUID allowlist policy at registration (`policy: { mode: 'allowlist', allow }`).
 *   • Audit hook (`onVerified`) recording the BS-bit flip when a single-device
 *     credential gets backed up to a multi-device sync (e.g. iCloud Keychain).
 *   • Counter-regression guard surfaced as `CounterRegressionError`.
 *   • Single-public-`authentication_failed` contract on the unknown-credential
 *     path — the granular reason stays on `error.details.reason` for logs.
 *
 * Run:  npx tsx examples/advanced-usage.ts
 */

import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistration,
  verifyAuthentication,
} from '@authkit/passkeys/server';
import { createMemoryCredentialStore } from '@authkit/passkeys/storage/memory';
import {
  AaguidNotAllowedError,
  AuthenticationFailedError,
  CounterRegressionError,
  isPasskeyError,
} from '@authkit/passkeys/errors';
import type {
  AaguidPolicy,
  AaguidString,
  AuthenticationVerifiedEvent,
  ChallengeSigningKeys,
  RegistrationVerifiedEvent,
} from '@authkit/passkeys/types';

import {
  createVirtualAuthenticator,
  simulateAuthentication,
  simulateRegistration,
} from './_simulator.js';

// --- Branded user-id ------------------------------------------------------

type UserId = string & { readonly __brand: 'UserId' };
const userId = (s: string): UserId => s as UserId;

const RP_ID = 'bank.example.com';
const ORIGIN = 'https://bank.example.com';

// --- Signing-key rotation -------------------------------------------------
// Old token issued under `k1` is still valid until TTL elapses while new
// tokens are minted under `k2`. PLAN §9.5.

const signingKeysOld: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'old-secret-rotated-on-2026-04-25-deploy' },
};
const signingKeysNew: ChallengeSigningKeys = {
  active: { kid: 'k2', secret: 'fresh-secret-active-since-2026-04-28' },
  previous: [{ kid: 'k1', secret: 'old-secret-rotated-on-2026-04-25-deploy' }],
};

// --- AAGUID allowlist (Apple platform + YubiKey 5 series, illustrative) ---

const APPLE_PLATFORM = 'adce0002-35bc-c60a-648b-0b25f1f05503' as AaguidString;
const YUBIKEY_5C = 'cb69481e-8ff7-4039-93ec-0a2729a154a8' as AaguidString;
const aaguidPolicy: AaguidPolicy = {
  mode: 'allowlist',
  allow: [APPLE_PLATFORM, YUBIKEY_5C],
  allowAnonymous: true, // attestation 'none' uses the all-zero AAGUID
};

// --- Audit sink (would be Sentry, Datadog, …) -----------------------------

const auditLog: Array<{ kind: string; payload: unknown }> = [];
const onRegistrationVerified = async (ev: RegistrationVerifiedEvent): Promise<void> => {
  auditLog.push({ kind: 'register', payload: ev });
};
const onAuthenticationVerified = async (ev: AuthenticationVerifiedEvent<UserId>): Promise<void> => {
  auditLog.push({ kind: 'login', payload: ev });
};

async function main(): Promise<void> {
  const store = createMemoryCredentialStore<UserId>();
  const alice: UserId = userId('user_alice');

  // ---- Registration: token issued under old key, verified post-rotation ---
  console.log('1) Register passkey — old key signs the challenge envelope.');
  const reg = await generateRegistrationOptions<UserId>({
    rp: { id: RP_ID, name: 'Bank' },
    user: { id: alice, name: 'alice@bank.example.com', displayName: 'Alice' },
    store,
    signingKeys: signingKeysOld,
    userVerification: 'required',
    authenticatorAttachment: 'platform',
  });

  const platform = await createVirtualAuthenticator({
    origin: ORIGIN,
    rpId: RP_ID,
    backupEligible: true, // iCloud-synced platform passkey
    backupState: false,
  });
  const regResponse = await simulateRegistration(platform, reg.options);

  // Now the deploy ships and the verifier flips to `signingKeysNew` — the
  // in-flight token signed under k1 still verifies because k1 sits in
  // `previous`. The AAGUID policy lets the all-zero anonymous AAGUID through
  // (`allowAnonymous: true`) since we asked for `attestation: 'none'`.
  const record = await verifyRegistration({
    response: regResponse,
    challengeToken: reg.challengeToken,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    signingKeys: signingKeysNew,
    policy: aaguidPolicy,
    onVerified: onRegistrationVerified,
  });
  await store.create({ ...record, userId: alice });
  console.log('   stored, deviceType =', record.deviceType, ', backupEligible =', record.backupEligible);

  // ---- Authentication: BS bit flips 0 → 1 (cred just got backed up) -------
  console.log('2) Login — BS bit flips, audit hook captures `newlyBackedUp`.');
  platform.backupState = true;

  const auth = await generateAuthenticationOptions<UserId>({
    rp: { id: RP_ID },
    user: { id: alice }, // non-discoverable — store fills allowCredentials
    store,
    signingKeys: signingKeysNew,
  });
  const authResponse = await simulateAuthentication(platform, auth.options);
  const verified = await verifyAuthentication<UserId>({
    response: authResponse,
    challengeToken: auth.challengeToken,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    store,
    signingKeys: signingKeysNew,
    onVerified: onAuthenticationVerified,
  });
  await store.updateCounter(verified.credential.credentialId, verified.newCounter);
  await store.updateBackupState(verified.credential.credentialId, true);
  const loginEvent = auditLog.at(-1)!.payload as AuthenticationVerifiedEvent<UserId>;
  console.log('   newlyBackedUp =', loginEvent.newlyBackedUp, ' (BS 0→1 detected)');

  // ---- Counter-regression guard -------------------------------------------
  console.log('3) Replay: rewind sign-counter — server rejects with CounterRegressionError.');
  platform.signCount = 0; // forge: pretend the cloned device never bumped
  const auth2 = await generateAuthenticationOptions<UserId>({
    rp: { id: RP_ID }, user: { id: alice }, store, signingKeys: signingKeysNew,
  });
  const replay = await simulateAuthentication(platform, auth2.options);
  // The simulator increments sign-count BEFORE signing, so signCount=1 vs
  // stored `verified.newCounter` (which was 1 before this turn) — to force
  // a regression we crank the stored counter forward.
  await store.updateCounter(verified.credential.credentialId, 999);
  try {
    await verifyAuthentication<UserId>({
      response: replay,
      challengeToken: auth2.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      store,
      signingKeys: signingKeysNew,
    });
    throw new Error('expected CounterRegressionError');
  } catch (err) {
    if (err instanceof CounterRegressionError) {
      console.log('   caught CounterRegressionError:', err.code);
    } else throw err;
  }

  // ---- Unknown credential collapses to a single public code ---------------
  console.log('4) Unknown credentialId — surface is `authentication_failed`, not `unknown_credential`.');
  const auth3 = await generateAuthenticationOptions<UserId>({
    rp: { id: RP_ID }, store, signingKeys: signingKeysNew,
  });
  const stranger = await createVirtualAuthenticator({ origin: ORIGIN, rpId: RP_ID });
  const strayResponse = await simulateAuthentication(stranger, auth3.options);
  try {
    await verifyAuthentication<UserId>({
      response: strayResponse,
      challengeToken: auth3.challengeToken,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      store,
      signingKeys: signingKeysNew,
    });
  } catch (err) {
    if (err instanceof AuthenticationFailedError) {
      // Public code — what your /api response would carry.
      console.log('   public  err.code =', err.code);
      console.log('   public  toJSON()  =', JSON.stringify(err.toJSON()));
      // Server-internal reason — kept on `details` for logs only.
      console.log('   server  reason   =', err.details?.reason);
    } else throw err;
  }

  // ---- AAGUID allowlist rejection ----------------------------------------
  console.log('5) Register a YubiKey-pretender with a forbidden AAGUID — rejected.');
  const banned = await createVirtualAuthenticator({
    origin: ORIGIN,
    rpId: RP_ID,
    aaguid: hexToBytes('00000000-0000-0000-0000-deadbeefcafe'),
  });
  const reg2 = await generateRegistrationOptions<UserId>({
    rp: { id: RP_ID, name: 'Bank' },
    user: { id: alice, name: 'alice@bank.example.com', displayName: 'Alice' },
    store, signingKeys: signingKeysNew,
    attestation: 'direct',
  });
  const banResponse = await simulateRegistration(banned, reg2.options);
  try {
    await verifyRegistration({
      response: banResponse,
      challengeToken: reg2.challengeToken,
      expectedOrigin: ORIGIN, expectedRpId: RP_ID,
      signingKeys: signingKeysNew,
      policy: { mode: 'allowlist', allow: [APPLE_PLATFORM, YUBIKEY_5C] },
    });
  } catch (err) {
    if (err instanceof AaguidNotAllowedError) {
      console.log('   caught AaguidNotAllowedError:', err.code, '|', err.details?.reason);
    } else if (isPasskeyError(err)) {
      console.log('   caught PasskeyError:', err.code);
    } else throw err;
  }

  console.log('\nAudit log entries:', auditLog.length, '(', auditLog.map((e) => e.kind).join(', '), ')');
}

function hexToBytes(uuid: string): Uint8Array {
  const clean = uuid.replace(/-/g, '');
  if (clean.length !== 32) throw new Error('expected 16-byte UUID');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
