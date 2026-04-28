import { NotSupportedError, PasskeyError } from '../errors/index.js';
import type {
  RegistrationOptionsJSON,
  RegistrationResponseJSON,
} from '../types/webauthn.js';
import { isPasskeySupported } from './feature-detection.js';
import { mapDomException } from './dom-error.js';
import { normalizeRegistrationResponse } from './normalize.js';
import { parseRegistrationOptions } from './parse-options.js';

/** Optional knobs for {@link startRegistration}. */
export interface RegisterInit {
  /** Abort the ceremony from your component lifecycle (e.g. on unmount). */
  signal?: AbortSignal;
  /**
   * Notification hook fired with the typed PasskeyError immediately before
   * it is rethrown. Return value is ignored — the rejection always
   * propagates. Use this for logging / analytics / routing side effects.
   * To suppress, wrap the call in try/catch yourself (PLAN §5.5).
   */
  onFallback?: (err: PasskeyError) => void | Promise<void>;
}

/**
 * Run the WebAuthn registration ceremony in the browser.
 *
 * Wraps `navigator.credentials.create()`. Accepts the JSON shape produced by
 * the server's {@link generateRegistrationOptions}, performs base64url
 * decoding internally, and returns a JSON-safe
 * {@link RegistrationResponseJSON} ready to POST back.
 *
 * @param options  Registration options as returned by the server.
 * @param init     Optional client-side knobs (`AbortSignal`, `onFallback`).
 * @returns        JSON-safe attestation response.
 * @throws {NotSupportedError}  When WebAuthn is unavailable.
 * @throws {UserCancelledError} When the user dismisses the prompt.
 * @throws {TimeoutError}       When the ceremony exceeds `options.timeout`.
 * @throws {InvalidStateError}  When the credential already exists for this user.
 * @throws {SecurityError}      When the browser refuses (RP-ID mismatch, etc.).
 *
 * @example
 *   const opts = await fetch('/api/passkey/register/options').then((r) => r.json());
 *   try {
 *     const response = await startRegistration(opts, {
 *       onFallback: (err) => analytics.track('passkey_register_failed', { code: err.code }),
 *     });
 *     await fetch('/api/passkey/register/verify', { method: 'POST', body: JSON.stringify(response) });
 *   } catch (err) {
 *     if (isPasskeyError(err) && err.code === 'not_supported') router.push('/login/password');
 *   }
 */
export async function startRegistration(
  options: RegistrationOptionsJSON,
  init?: RegisterInit,
): Promise<RegistrationResponseJSON> {
  if (!isPasskeySupported()) {
    const err = new NotSupportedError();
    if (init?.onFallback) await init.onFallback(err);
    throw err;
  }

  const publicKey = parseRegistrationOptions(options);
  let credential: PublicKeyCredential | null;
  try {
    credential = (await navigator.credentials.create({
      publicKey,
      ...(init?.signal ? { signal: init.signal } : {}),
    })) as PublicKeyCredential | null;
  } catch (cause) {
    const mapped = mapDomException(cause);
    if (init?.onFallback) await init.onFallback(mapped);
    throw mapped;
  }

  if (!credential) {
    const err = new NotSupportedError(
      'navigator.credentials.create resolved to null. The UA likely refused the ceremony.',
    );
    if (init?.onFallback) await init.onFallback(err);
    throw err;
  }

  return normalizeRegistrationResponse(credential);
}
