import type {
  AuthenticationOptionsJSON,
  AuthenticationResponseJSON,
} from '../types/webauthn.js';
import {
  startAuthentication,
  type AuthenticateInit,
} from './start-authentication.js';

/** Handle returned by {@link startConditionalUI}. */
export interface ConditionalUIHandle {
  /** Resolves with the assertion when the user picks a passkey from autofill. */
  readonly result: Promise<AuthenticationResponseJSON>;
  /** Cancel the conditional ceremony — call from your form-submit handler. */
  cancel(): void;
}

/**
 * Convenience wrapper that runs {@link startAuthentication} with
 * `mediation: 'conditional'` and bundles the AbortController so callers
 * can cancel the ceremony cleanly when the user picks a non-passkey path
 * (e.g. types an email + clicks "send magic link").
 *
 * @param options  Authentication options as returned by the server.
 * @param init     Optional knobs (forwarded to {@link startAuthentication}).
 * @returns        `{ result, cancel }`.
 *
 * @example
 *   const { result, cancel } = startConditionalUI(opts, { onFallback: log });
 *   form.addEventListener('submit', cancel);
 *   const response = await result;
 */
export function startConditionalUI(
  options: AuthenticationOptionsJSON,
  init?: Omit<AuthenticateInit, 'mediation' | 'signal'>,
): ConditionalUIHandle {
  const ctrl = new AbortController();
  const result = startAuthentication(options, {
    ...(init ?? {}),
    mediation: 'conditional',
    signal: ctrl.signal,
  });
  return {
    result,
    cancel(): void {
      ctrl.abort();
    },
  };
}
