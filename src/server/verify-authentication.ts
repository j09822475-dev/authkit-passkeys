import {
  AuthenticationFailedError,
  CounterRegressionError,
  InvalidRpIdError,
} from '../errors/classes.js';
import { assertBase64Url, fromBase64Url } from '../core/encoding/base64url.js';
import { encodeUtf8 } from '../core/encoding/utf8.js';
import { sha256 } from '../core/crypto/digest.js';
import { concatBytes, equalBytes } from '../core/crypto/bytes.js';
import { dummyVerify, verifySignature } from '../core/crypto/verify.js';
import { parseCoseKey } from '../core/cose/key.js';
import {
  assertExpectedClientData,
  assertOriginMatchesRpId,
  parseAuthenticatorData,
  parseClientDataJSON,
} from '../core/ceremony/index.js';
import { verifyChallengeToken } from './challenge.js';
import { assertUserVerification } from './policy/user-verification.js';
import type { CredentialStore } from '../storage/types.js';
import type {
  AuthenticationResponseJSON,
  Base64Url,
  ChallengeToken,
} from '../types/webauthn.js';
import type {
  AuthenticationVerifiedEvent,
  CredentialRecord,
  VerifiedAuthentication,
} from '../types/credential.js';
import type { ChallengeSigningKeys } from '../types/options.js';

/** Input shape for {@link verifyAuthentication}. */
export interface VerifyAuthenticationInput<TUserId extends string> {
  response: AuthenticationResponseJSON;
  challengeToken: ChallengeToken | string;
  expectedOrigin: string | readonly string[];
  expectedRpId: string;
  store: CredentialStore<TUserId>;
  signingKeys: ChallengeSigningKeys;
  /** Default `true`. */
  requireUserVerification?: boolean;
  /** Hook fired after verification. Errors thrown propagate. */
  onVerified?: (ev: AuthenticationVerifiedEvent<TUserId>) => void | Promise<void>;
}

/**
 * Verify the assertion produced by the browser's {@link startAuthentication}.
 *
 * The single-public-`authentication_failed` contract holds end-to-end:
 * unknown credential, signature mismatch, malformed signature, and BE-bit
 * regression all surface as {@link AuthenticationFailedError} (with the
 * granular reason on `error.details.reason` for server logs only). The
 * unknown-credential path runs a synthetic {@link dummyVerify} so request
 * duration matches the verifying branch (PLAN §5.6 / §9.10 / §9.14).
 *
 * The store is consulted once for the credential lookup. The caller is
 * responsible for persisting the new counter via `store.updateCounter` (and
 * `store.updateBackupState` if the BS bit flipped) after their
 * session-creation transaction commits.
 *
 * @param input  Verification input — see {@link VerifyAuthenticationInput}.
 * @returns      {@link VerifiedAuthentication} — `userId`, `credential`, `newCounter`.
 * @throws {InvalidChallengeTokenError}    Tag mismatch / expired / malformed.
 * @throws {WrongCeremonyError}            Token issued for the registration ceremony.
 * @throws {InvalidChallengeError}         clientData challenge mismatch.
 * @throws {InvalidOriginError}            Origin not allowed.
 * @throws {InvalidRpIdError}              `authData.rpIdHash` mismatch.
 * @throws {AuthenticationFailedError}     Unknown credential, bad signature, malformed sig, or BE flag regression.
 * @throws {UserVerificationRequiredError} UV required but `flags.uv` is 0.
 * @throws {CounterRegressionError}        Sign-counter strictly less than stored value.
 *
 * @example
 *   const result = await verifyAuthentication({
 *     response: req.body,
 *     challengeToken: getCookie('passkey_auth')!,
 *     expectedOrigin: 'https://example.com',
 *     expectedRpId: 'example.com',
 *     store,
 *     signingKeys: PASSKEY_SIGNING_KEYS,
 *   });
 *   await store.updateCounter(result.credential.credentialId, result.newCounter);
 *   await session.create(result.userId);
 */
export async function verifyAuthentication<TUserId extends string>(
  input: VerifyAuthenticationInput<TUserId>,
): Promise<VerifiedAuthentication<TUserId>> {
  const requireUv = input.requireUserVerification ?? true;

  const { challenge: expectedChallenge } = await verifyChallengeToken(
    input.challengeToken,
    input.signingKeys,
    'auth',
  );

  // Always decode + validate clientData first — bad challenge / bad origin should
  // fail identically regardless of credentialId (no enumeration oracle).
  const clientDataBytes = fromBase64Url(input.response.response.clientDataJSON);
  const clientData = parseClientDataJSON(clientDataBytes);
  assertExpectedClientData(clientData, 'webauthn.get', expectedChallenge, input.expectedOrigin);
  assertOriginMatchesRpId(clientData.origin, input.expectedRpId);

  const authDataBytes = fromBase64Url(input.response.response.authenticatorData);
  const authData = parseAuthenticatorData(authDataBytes);

  const expectedRpIdHash = await sha256(encodeUtf8(input.expectedRpId));
  if (!equalBytes(authData.rpIdHash, expectedRpIdHash)) {
    throw new InvalidRpIdError(undefined, {
      details: { reason: 'rp_id_hash_mismatch', expectedRpId: input.expectedRpId },
    });
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64Url(input.response.response.signature);
  } catch (cause) {
    // Malformed signature collapses to authentication_failed (PLAN §9.3).
    throw new AuthenticationFailedError(undefined, {
      cause,
      details: { reason: 'invalid_signature' },
    });
  }

  const clientDataHash = await sha256(clientDataBytes);
  const signedData = concatBytes(authDataBytes, clientDataHash);

  // Credential lookup (PLAN §9.10). Both branches end up running a real WebCrypto
  // verify so timing does not branch on credential existence. The id from the
  // response is untrusted — validate the base64url alphabet at the trust
  // boundary before it reaches the store, and collapse failures into the
  // single public `authentication_failed` bucket.
  let credentialId: Base64Url;
  try {
    credentialId = assertBase64Url(input.response.id);
  } catch (cause) {
    await dummyVerify(signedData);
    throw new AuthenticationFailedError(undefined, {
      cause,
      details: { reason: 'unknown_credential' },
    });
  }
  const credential = await input.store.findByCredentialId(credentialId);
  if (!credential) {
    await dummyVerify(signedData);
    throw new AuthenticationFailedError(undefined, {
      details: { reason: 'unknown_credential', credentialId },
    });
  }

  const coseKey = parseCoseKey(fromBase64Url(credential.publicKey));

  let signatureValid = false;
  try {
    signatureValid = await verifySignature(coseKey, signature, signedData);
  } catch (cause) {
    throw new AuthenticationFailedError(undefined, {
      cause,
      details: { reason: 'invalid_signature', credentialId },
    });
  }
  if (!signatureValid) {
    throw new AuthenticationFailedError(undefined, {
      details: { reason: 'invalid_signature', credentialId },
    });
  }

  // BE bit must not regress 1 → 0 (PLAN §9.6 / WebAuthn).
  if (credential.backupEligible && !authData.flags.be) {
    throw new AuthenticationFailedError(
      'Backup-eligibility flag regressed (BE: 1 → 0 is forbidden).',
      { details: { reason: 'backup_eligibility_flipped', credentialId } },
    );
  }

  assertUserVerification(authData.flags, requireUv);

  // Counter handling — 0 → 0 is legitimate for sync passkeys; strict-less is regression.
  if (authData.signCount !== 0 || credential.counter !== 0) {
    if (authData.signCount < credential.counter) {
      throw new CounterRegressionError(undefined, {
        details: { reason: 'sign_count_regressed', credentialId },
      });
    }
  }

  const newCounter = authData.signCount;
  const newlyBackedUp = !credential.backupState && authData.flags.bs;

  const persistedCredential: CredentialRecord<TUserId> = {
    ...credential,
    counter: newCounter,
    backupState: authData.flags.bs,
  };

  if (input.onVerified) {
    await input.onVerified({
      userId: credential.userId,
      credentialId,
      newCounter,
      flags: {
        up: authData.flags.up,
        uv: authData.flags.uv,
        be: authData.flags.be,
        bs: authData.flags.bs,
      },
      newlyBackedUp,
    });
  }

  return {
    userId: credential.userId,
    credential: persistedCredential,
    newCounter,
    userVerified: authData.flags.uv,
  };
}

