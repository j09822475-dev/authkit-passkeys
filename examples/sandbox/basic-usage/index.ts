/**
 * Minimal end-to-end passkey ceremony.
 *
 * Demonstrates the four `@authkit/passkeys` server calls in the order a real
 * app would chain them:
 *
 *   1. generateRegistrationOptions  → server mints challenge envelope
 *   2. startRegistration            → browser ceremony (here: simulated)
 *   3. verifyRegistration           → server validates attestation, returns record
 *   4. generateAuthenticationOptions → fresh challenge for login
 *   5. startAuthentication          → browser ceremony (here: simulated)
 *   6. verifyAuthentication         → server validates assertion
 *
 * Run:  npx tsx examples/basic-usage.ts
 */

import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistration,
  verifyAuthentication,
} from '@authkit/passkeys/server';
import { createMemoryCredentialStore } from '@authkit/passkeys/storage/memory';
import type { ChallengeSigningKeys } from '@authkit/passkeys/types';

import { createVirtualAuthenticator, simulateAuthentication, simulateRegistration } from './_simulator.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const signingKeys: ChallengeSigningKeys = {
  active: { kid: 'k1', secret: 'replace-me-with-a-32-byte-random-secret' },
};

async function main(): Promise<void> {
  const store = createMemoryCredentialStore();
  const user = { id: 'user_alice', name: 'alice@example.com', displayName: 'Alice' };

  // ---- Registration -------------------------------------------------------
  console.log('1) generateRegistrationOptions');
  const reg = await generateRegistrationOptions({
    rp: { id: RP_ID, name: 'Example' },
    user,
    store,
    signingKeys,
  });
  console.log('   challenge =', reg.options.challenge);
  console.log('   token (first 32 chars) =', reg.challengeToken.slice(0, 32) + '…');

  // The browser would now run navigator.credentials.create(). Stand in for it.
  const authenticator = await createVirtualAuthenticator({ origin: ORIGIN, rpId: RP_ID });
  const regResponse = await simulateRegistration(authenticator, reg.options);

  console.log('2) verifyRegistration');
  const newRecord = await verifyRegistration({
    response: regResponse,
    challengeToken: reg.challengeToken,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    signingKeys,
  });
  await store.create({ ...newRecord, userId: user.id });
  console.log('   credentialId =', newRecord.credentialId);
  console.log('   deviceType   =', newRecord.deviceType);

  // ---- Authentication ----------------------------------------------------
  console.log('3) generateAuthenticationOptions (discoverable / passkey-first)');
  const auth = await generateAuthenticationOptions({
    rp: { id: RP_ID },
    store,
    signingKeys,
  });

  const authResponse = await simulateAuthentication(authenticator, auth.options);

  console.log('4) verifyAuthentication');
  const verified = await verifyAuthentication({
    response: authResponse,
    challengeToken: auth.challengeToken,
    expectedOrigin: ORIGIN,
    expectedRpId: RP_ID,
    store,
    signingKeys,
  });
  await store.updateCounter(verified.credential.credentialId, verified.newCounter);

  console.log('   userId       =', verified.userId);
  console.log('   userVerified =', verified.userVerified);
  console.log('   newCounter   =', verified.newCounter);
  console.log('\nDone — login succeeded.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
