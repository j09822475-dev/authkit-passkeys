import { NotSupportedError, PasskeyError } from '../errors/index.js';
import type {
  AuthenticationOptionsJSON,
  AuthenticationResponseJSON,
} from '../types/webauthn.js';
import {
  isConditionalUISupported,
  isPasskeySupported,
} from './feature-detection.js';
import { mapDomException } from './dom-error.js';
import { normalizeAuthenticationResponse } from './normalize.js';
import { parseAuthenticationOptions } from './parse-options.js';

/** Optional knobs for {@link startAuthentication}. */
export interface AuthenticateInit {
  /** Abort the ceremony — required for Conditional UI cleanup on form submit. */
  signal?: AbortSignal;
  /** Notification hook (fire-and-forget; the rejection always propagates). */
  onFallback?: (err: PasskeyError) => void | Promise<void>;
  /**
   * `'conditional'` opts into autofill UI (requires
   * `isConditionalUISupported()`); `'required'` forces a UI prompt;
   * `'optional'` is the browser default. The WebAuthn `'silent'` value is
   * intentionally excluded — it does not apply to passkey ceremonies (PLAN §9.8).
   */
  mediation?: 'conditional' | 'optional' | 'required';
}

/**
 * Run the WebAuthn authentication ceremony in the browser.
 *
 * Wraps `navigator.credentials.get()`. Pass `mediation: 'conditional'` to
 * enable autofill UI — the input element receiving
 * `autocomplete="username webauthn"` will surface available passkeys.
 * Callers MUST gate the `'conditional'` path on a successful
 * {@link isConditionalUISupported} check; this function throws
 * {@link NotSupportedError} synchronously when Conditional UI is not
 * available (PLAN §9.8).
 *
 * @param options  Authentication options as returned by the server.
 * @param init     Optional client-side knobs.
 * @returns        JSON-safe assertion response.
 * @throws {NotSupportedError}  WebAuthn unavailable, OR `'conditional'` requested but unsupported.
 * @throws {UserCancelledError} User dismissed (or the AbortController fired).
 * @throws {TimeoutError}       Ceremony exceeded `options.timeout`.
 * @throws {SecurityError}      Browser refused for security reasons.
 *
 * @example  Discoverable login (no username collected):
 *   const opts = await fetch('/api/passkey/login/options').then((r) => r.json());
 *   const response = await startAuthentication(opts);
 *
 * @example  Conditional UI:
 *   if (!(await isConditionalUISupported())) return;
 *   const ctrl = new AbortController();
 *   startAuthentication(opts, { mediation: 'conditional', signal: ctrl.signal })
 *     .then(handleLogin)
 *     .catch(() => {});
 */
export async function startAuthentication(
  options: AuthenticationOptionsJSON,
  init?: AuthenticateInit,
): Promise<AuthenticationResponseJSON> {
  if (!isPasskeySupported()) {
    const err = new NotSupportedError();
    if (init?.onFallback) await init.onFallback(err);
    throw err;
  }

  if (init?.mediation === 'conditional' && !(await isConditionalUISupported())) {
    const err = new NotSupportedError('Conditional Mediation is not supported by this browser.');
    if (init.onFallback) await init.onFallback(err);
    throw err;
  }

  const publicKey = parseAuthenticationOptions(options);
  const startedAt = Date.now();
  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.get({
      publicKey,
      ...(init?.mediation ? { mediation: init.mediation as CredentialMediationRequirement } : {}),
      ...(init?.signal ? { signal: init.signal } : {}),
    })) as PublicKeyCredential | null;
  } catch (cause) {
    const mapped = mapDomException(cause, Date.now() - startedAt);
    if (init?.onFallback) await init.onFallback(mapped);
    throw mapped;
  }

  if (!credential) {
    const err = new NotSupportedError(
      'navigator.credentials.get resolved to null. The UA likely refused the ceremony.',
    );
    if (init?.onFallback) await init.onFallback(err);
    throw err;
  }

  return normalizeAuthenticationResponse(credential);
}
