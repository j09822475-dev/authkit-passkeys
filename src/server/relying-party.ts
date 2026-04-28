import { PasskeyError } from '../errors/base.js';
import { PasskeyVerificationError } from '../errors/verification.js';
import { PasskeyPolicyError } from '../errors/policy.js';
import { PasskeyInternalError } from '../errors/internal.js';
import type {
  AttestationConveyancePreference,
  AuthenticationResponseJSON,
  ChallengeToken,
  PasskeyExtensionsInput,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '../types/webauthn-json.js';
import type { AuthenticatedCredential, CredentialRecord } from '../types/credential.js';
import type {
  AuthenticatorPolicy,
  AuthenticatorPolicyOverride,
  RpConfigOverride,
} from '../types/policy.js';
import { ok, err, type Result } from '../core/result.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import {
  type AttestationVerifier,
} from '../core/attestation-formats/index.js';
import { deriveRpIdFromOrigin } from '../core/ceremony/rp-id.js';
import { _buildRegistrationOptions } from './options-registration.js';
import { _buildAuthenticationOptions } from './options-authentication.js';
import { _verifyRegistration } from './verify-registration.js';
import { _verifyAuthentication } from './verify-authentication.js';
import { mergePolicy } from './policies.js';
import {
  DEFAULT_ATTESTATION,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_POLICY,
  DEFAULT_TIMEOUT_MS,
} from './defaults.js';
import { type ChallengeStore } from './challenge.js';
import { type CredentialStore } from './credential-store.js';
import { emitAudit, type AuditHook } from './audit.js';

/**
 * Context handed to {@link RpConfig.resolveConfig} for per-request /
 * multi-tenant overrides.
 */
export interface ResolveConfigContext {
  /** Optional hostname extracted from the inbound request — useful for tenant lookup. */
  hostname?: string;
  /** Optional headers map for further routing. */
  headers?: Readonly<Record<string, string>>;
  /** Free-form pass-through (caller's choice). */
  context?: unknown;
}

/**
 * Configuration for {@link RelyingParty}. Most fields are optional with sensible
 * defaults; `rpName`, `challengeStore`, and `credentialStore` are required.
 *
 * For multi-tenant deploys, supply `resolveConfig` and omit `rpId` / `origin`
 * — the callback returns them per-request.
 */
export interface RpConfig {
  rpName: string;
  rpId?: string;
  origin?: string | readonly string[];
  defaultTimeoutMs?: number;
  challengeStore: ChallengeStore;
  credentialStore: CredentialStore;
  policy?: Partial<AuthenticatorPolicy>;
  audit?: AuditHook;
  attestation?: AttestationConveyancePreference;
  /** Per-request override hook. Anything returned wins over the constructor defaults. */
  resolveConfig?: (ctx: ResolveConfigContext) => Promise<RpConfigOverride> | RpConfigOverride;
  /** Override / extend the default attestation verifier registry. */
  attestationVerifiers?: ReadonlyMap<string, AttestationVerifier>;
  /** Default challenge TTL — defaults to {@link DEFAULT_CHALLENGE_TTL_MS} (5 minutes). */
  challengeTtlMs?: number;
}

export interface StartRegistrationInput {
  user: { id: Uint8Array; name: string; displayName: string };
  excludeCredentials?: ReadonlyArray<{ id: string; transports?: readonly string[] }>;
  attestation?: AttestationConveyancePreference;
  extensions?: PasskeyExtensionsInput;
  policy?: AuthenticatorPolicyOverride;
  timeoutMs?: number;
  /** Per-request context fed to `resolveConfig`. */
  ceremonyContext?: ResolveConfigContext;
}

export interface StartRegistrationOutput {
  options: PublicKeyCredentialCreationOptionsJSON;
  challengeToken: ChallengeToken;
}

export interface FinishRegistrationInput {
  response: RegistrationResponseJSON;
  challengeToken: ChallengeToken | string;
  expectedUserId: Uint8Array;
  policy?: AuthenticatorPolicyOverride;
  ceremonyContext?: ResolveConfigContext;
}

export interface StartAuthenticationInput {
  /** Optional — when omitted, `userId` triggers `findByUserId` lookup; absent both = discoverable flow. */
  userId?: Uint8Array;
  allowCredentials?: ReadonlyArray<{ id: string; transports?: readonly string[] }>;
  extensions?: PasskeyExtensionsInput;
  policy?: AuthenticatorPolicyOverride;
  timeoutMs?: number;
  ceremonyContext?: ResolveConfigContext;
}

export interface StartAuthenticationOutput {
  options: PublicKeyCredentialRequestOptionsJSON;
  challengeToken: ChallengeToken;
}

export interface FinishAuthenticationInput {
  response: AuthenticationResponseJSON;
  challengeToken: ChallengeToken | string;
  /** When set, `response.userHandle` (or stored userId) MUST match. */
  expectedUserId?: Uint8Array;
  policy?: AuthenticatorPolicyOverride;
  ceremonyContext?: ResolveConfigContext;
}

/**
 * Central handle for a Relying Party. Stateless except via its injected
 * {@link ChallengeStore} and {@link CredentialStore}. The four ceremony
 * methods cover the full WebAuthn flow; everything else (multi-tenant config,
 * per-call policy override) flows through their inputs.
 *
 * @example
 *   const rp = new RelyingParty({
 *     rpName: 'Acme',
 *     rpId: 'acme.com',
 *     origin: 'https://acme.com',
 *     challengeStore: new InMemoryChallengeStore(),
 *     credentialStore: new MyStore(),
 *   });
 *
 *   const { options, challengeToken } = await rp.startRegistration({ user });
 *   // ... browser ceremony ...
 *   const r = await rp.finishRegistration({ response, challengeToken, expectedUserId: user.id });
 *   if (r.ok) await store.save(r.value);
 */
export class RelyingParty {
  readonly #config: RpConfig;
  readonly #policy: AuthenticatorPolicy;

  /**
   * @param config  Configuration. `rpName`, `challengeStore`, and `credentialStore` are required.
   * @throws {PasskeyInternalError}  When required fields are missing.
   */
  constructor(config: RpConfig) {
    if (!config) throw new PasskeyInternalError('RelyingParty: config is required.');
    if (!config.rpName) throw new PasskeyInternalError('RelyingParty: rpName is required.');
    if (!config.challengeStore) throw new PasskeyInternalError('RelyingParty: challengeStore is required.');
    if (!config.credentialStore) throw new PasskeyInternalError('RelyingParty: credentialStore is required.');
    this.#config = config;
    this.#policy = {
      ...DEFAULT_POLICY,
      ...(config.policy ?? {}),
    } as AuthenticatorPolicy;
  }

  /**
   * Build options for `navigator.credentials.create`. Persists the challenge
   * via the configured {@link ChallengeStore}; round-trip the returned
   * `challengeToken` to {@link finishRegistration}.
   *
   * @param input  Registration ceremony input — see {@link StartRegistrationInput}.
   * @returns      `{ options, challengeToken }` — pass `options` to the browser, persist `challengeToken`.
   * @throws {PasskeyInternalError}  When config is incomplete (no rpId resolvable).
   *
   * @example
   *   const { options, challengeToken } = await rp.startRegistration({ user: { id, name, displayName } });
   *   res.json({ options, challengeToken });
   */
  async startRegistration(input: StartRegistrationInput): Promise<StartRegistrationOutput> {
    const resolved = await this.#resolve(input.ceremonyContext);
    const policy = mergePolicy(this.#policy, input.policy);

    let excludeCredentials = input.excludeCredentials;
    if (!excludeCredentials) {
      const stored = await this.#config.credentialStore.findByUserId(input.user.id);
      excludeCredentials = stored.map((c) => ({ id: c.credentialId, transports: c.transports }));
    }

    const { options, challenge } = _buildRegistrationOptions({
      rpName: resolved.rpName,
      rpId: resolved.rpId,
      policy,
      user: input.user,
      excludeCredentials,
      attestation: input.attestation ?? this.#config.attestation ?? DEFAULT_ATTESTATION,
      extensions: input.extensions,
      timeoutMs: input.timeoutMs ?? resolved.defaultTimeoutMs,
    });

    const challengeToken = (await this.#config.challengeStore.issue({
      challenge,
      userId: input.user.id,
      ttlMs: this.#config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS,
    })) as ChallengeToken;

    await emitAudit(this.#config.audit, {
      type: 'registration.start',
      userId: toBase64Url(input.user.id),
      timestamp: Date.now(),
    });

    return { options, challengeToken };
  }

  /**
   * Verify a registration response. Returns a {@link Result} — never throws on
   * verification failure (only on programmer error like missing config).
   *
   * @param input  Finish-registration input.
   * @returns      `Result<CredentialRecord, PasskeyVerificationError | PasskeyPolicyError>`
   *
   * @example
   *   const r = await rp.finishRegistration({ response, challengeToken, expectedUserId });
   *   if (!r.ok) return res.status(400).json({ code: r.error.code });
   *   await store.save(r.value);
   */
  async finishRegistration(
    input: FinishRegistrationInput,
  ): Promise<Result<CredentialRecord, PasskeyVerificationError | PasskeyPolicyError>> {
    const resolved = await this.#resolve(input.ceremonyContext);
    const policy = mergePolicy(this.#policy, input.policy);

    const consumed = await this.#config.challengeStore.consume(String(input.challengeToken));
    if (!consumed) {
      const error = new PasskeyVerificationError('bad-challenge', 'Challenge token is invalid or expired.', {
        details: { reason: 'challenge-expired' },
      });
      await this.#auditFailure('registration', error, input.expectedUserId);
      return err(error);
    }

    if (consumed.userId && !equalBytes(consumed.userId, input.expectedUserId)) {
      const error = new PasskeyVerificationError(
        'registration-failed',
        'Challenge token belongs to a different user.',
        { details: { reason: 'unknown-credential' } },
      );
      await this.#auditFailure('registration', error, input.expectedUserId);
      return err(error);
    }

    try {
      const record = await _verifyRegistration({
        response: input.response,
        expectedChallenge: consumed.challenge,
        expectedOrigin: this.#requireOrigin(resolved),
        expectedRpId: this.#requireRpId(resolved),
        expectedUserId: input.expectedUserId,
        attestation: input.response ? (this.#config.attestation ?? DEFAULT_ATTESTATION) : DEFAULT_ATTESTATION,
        policy,
        attestationVerifiers: this.#config.attestationVerifiers ?? new Map<string, AttestationVerifier>(),
      });
      await emitAudit(this.#config.audit, {
        type: 'registration.success',
        credentialId: record.credentialId,
        aaguid: record.aaguid,
        userId: toBase64Url(record.userId),
        timestamp: Date.now(),
      });
      return ok(record);
    } catch (e) {
      if (e instanceof PasskeyVerificationError || e instanceof PasskeyPolicyError) {
        await this.#auditFailure('registration', e, input.expectedUserId);
        return err(e);
      }
      // Unknown -> normalize to a verification error so the caller's contract holds.
      const wrapped = new PasskeyVerificationError(
        'registration-failed',
        e instanceof Error ? e.message : 'Registration failed.',
        {
          cause: e,
          details: e instanceof PasskeyError && e.details ? e.details : { reason: 'attestation-statement-invalid' },
        },
      );
      await this.#auditFailure('registration', wrapped, input.expectedUserId);
      return err(wrapped);
    }
  }

  /**
   * Build options for `navigator.credentials.get`. Empty `allowCredentials`
   * triggers the discoverable-credential (passwordless) flow; the server then
   * resolves the user from the response's `userHandle`.
   *
   * @param input  Optional authentication input.
   * @returns      `{ options, challengeToken }`
   *
   * @example
   *   const { options, challengeToken } = await rp.startAuthentication({ userId });
   */
  async startAuthentication(input: StartAuthenticationInput = {}): Promise<StartAuthenticationOutput> {
    const resolved = await this.#resolve(input.ceremonyContext);
    const policy = mergePolicy(this.#policy, input.policy);

    let allowCredentials = input.allowCredentials;
    if (!allowCredentials && input.userId) {
      const stored = await this.#config.credentialStore.findByUserId(input.userId);
      allowCredentials = stored.map((c) => ({ id: c.credentialId, transports: c.transports }));
    }
    allowCredentials ??= [];

    const { options, challenge } = _buildAuthenticationOptions({
      rpId: resolved.rpId,
      policy,
      allowCredentials,
      extensions: input.extensions,
      timeoutMs: input.timeoutMs ?? resolved.defaultTimeoutMs,
    });

    const challengeToken = (await this.#config.challengeStore.issue({
      challenge,
      ...(input.userId ? { userId: input.userId } : {}),
      ttlMs: this.#config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS,
    })) as ChallengeToken;

    await emitAudit(this.#config.audit, {
      type: 'authentication.start',
      ...(input.userId ? { userId: toBase64Url(input.userId) } : {}),
      timestamp: Date.now(),
    });

    return { options, challengeToken };
  }

  /**
   * Verify an authentication response. Returns a {@link Result} — never throws
   * on verification failure.
   *
   * The returned {@link AuthenticatedCredential} carries the new sign-counter;
   * the caller MUST persist it (and `signCountStatic` if changed) atomically
   * with session creation.
   *
   * @param input  Finish-authentication input.
   * @returns      `Result<AuthenticatedCredential, PasskeyVerificationError | PasskeyPolicyError>`
   *
   * @example
   *   const r = await rp.finishAuthentication({ response, challengeToken });
   *   if (!r.ok) return reject({ code: r.error.code }); // never forward .details
   *   await session.create(r.value.userId);
   */
  async finishAuthentication(
    input: FinishAuthenticationInput,
  ): Promise<Result<AuthenticatedCredential, PasskeyVerificationError | PasskeyPolicyError>> {
    const resolved = await this.#resolve(input.ceremonyContext);
    const policy = mergePolicy(this.#policy, input.policy);

    const consumed = await this.#config.challengeStore.consume(String(input.challengeToken));
    if (!consumed) {
      const error = new PasskeyVerificationError('bad-challenge', 'Challenge token is invalid or expired.', {
        details: { reason: 'challenge-expired' },
      });
      await this.#auditFailure('authentication', error);
      return err(error);
    }

    let credential: CredentialRecord | null = null;
    try {
      credential = await this.#config.credentialStore.findById(input.response.id);
    } catch (cause) {
      // Treat lookup failure as authentication-failed at the public boundary;
      // the audit hook gets the underlying details.
      const wrapped = new PasskeyVerificationError('authentication-failed', 'Credential lookup failed.', {
        cause,
        details: { reason: 'unknown-credential', credentialId: input.response.id },
      });
      await this.#auditFailure('authentication', wrapped);
      return err(wrapped);
    }

    try {
      const { result, patch } = await _verifyAuthentication({
        response: input.response,
        expectedChallenge: consumed.challenge,
        expectedOrigin: this.#requireOrigin(resolved),
        expectedRpId: this.#requireRpId(resolved),
        ...(input.expectedUserId ? { expectedUserId: input.expectedUserId } : {}),
        policy,
        credential,
      });

      if (credential) {
        await this.#config.credentialStore.update(credential.credentialId, patch);
      }

      await emitAudit(this.#config.audit, {
        type: 'authentication.success',
        credentialId: result.credentialId,
        userId: toBase64Url(result.userId),
        timestamp: Date.now(),
      });
      return ok(result);
    } catch (e) {
      if (e instanceof PasskeyVerificationError || e instanceof PasskeyPolicyError) {
        await this.#auditFailure('authentication', e);
        return err(e);
      }
      const wrapped = new PasskeyVerificationError(
        'authentication-failed',
        e instanceof Error ? e.message : 'Authentication failed.',
        {
          cause: e,
          details: e instanceof PasskeyError && e.details ? e.details : { reason: 'bad-signature' },
        },
      );
      await this.#auditFailure('authentication', wrapped);
      return err(wrapped);
    }
  }

  // ---------- helpers ----------

  async #resolve(ctx: ResolveConfigContext | undefined): Promise<{
    rpName: string;
    rpId: string | undefined;
    origin: string | readonly string[] | undefined;
    defaultTimeoutMs: number;
  }> {
    let override: RpConfigOverride = {};
    if (this.#config.resolveConfig) {
      override = await this.#config.resolveConfig(ctx ?? {});
    }
    const rpName = override.rpName ?? this.#config.rpName;
    const origin = override.origin ?? this.#config.origin;
    let rpId = override.rpId ?? this.#config.rpId;
    if (!rpId && origin) {
      const first = typeof origin === 'string' ? origin : origin[0];
      if (first) rpId = deriveRpIdFromOrigin(first);
    }
    return {
      rpName,
      rpId,
      origin,
      defaultTimeoutMs: override.defaultTimeoutMs ?? this.#config.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS,
    };
  }

  #requireRpId(resolved: { rpId: string | undefined }): string {
    if (!resolved.rpId) {
      throw new PasskeyInternalError(
        'RelyingParty: rpId is required (set on config, derived from origin, or returned from resolveConfig).',
      );
    }
    return resolved.rpId;
  }

  #requireOrigin(resolved: {
    origin: string | readonly string[] | undefined;
  }): string | readonly string[] {
    if (!resolved.origin) {
      throw new PasskeyInternalError(
        'RelyingParty: origin is required (set on config or returned from resolveConfig).',
      );
    }
    return resolved.origin;
  }

  async #auditFailure(
    kind: 'registration' | 'authentication',
    error: PasskeyError,
    userId?: Uint8Array,
  ): Promise<void> {
    const event =
      kind === 'registration'
        ? {
            type: 'registration.failure' as const,
            code: error.code,
            ...(error.details && typeof error.details['reason'] === 'string'
              ? { reason: error.details['reason'] as string }
              : {}),
            ...(userId ? { userId: toBase64Url(userId) } : {}),
            timestamp: Date.now(),
          }
        : {
            type: 'authentication.failure' as const,
            code: error.code,
            ...(error.details && typeof error.details['reason'] === 'string'
              ? { reason: error.details['reason'] as string }
              : {}),
            ...(error.details && typeof error.details['credentialId'] === 'string'
              ? { credentialId: error.details['credentialId'] as string }
              : {}),
            timestamp: Date.now(),
          };
    await emitAudit(this.#config.audit, event);
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
