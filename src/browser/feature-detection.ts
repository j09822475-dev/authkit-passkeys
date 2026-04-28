/**
 * Synchronous feature detection: does the UA expose
 * `navigator.credentials.create/get` and `PublicKeyCredential`?
 *
 * @returns  `true` iff the WebAuthn API is reachable.
 *
 * @example
 *   if (!isPasskeySupported()) router.push('/login/password');
 */
export function isPasskeySupported(): boolean {
  if (typeof globalThis === 'undefined') return false;
  const win = globalThis as unknown as {
    navigator?: { credentials?: { create?: unknown; get?: unknown } };
    PublicKeyCredential?: unknown;
  };
  return (
    typeof win.PublicKeyCredential !== 'undefined' &&
    typeof win.navigator?.credentials?.create === 'function' &&
    typeof win.navigator?.credentials?.get === 'function'
  );
}

/**
 * Async feature detection: does the UA support Conditional Mediation
 * (autofill UI in `<input autocomplete="username webauthn">`)?
 *
 * The spec requires this to be async because the result depends on UA state
 * that may not be ready synchronously.
 *
 * @returns  Promise resolving to `true` iff Conditional UI is available.
 *
 * @example
 *   if (await isConditionalUISupported()) await startAuthentication(opts, { mediation: 'conditional' });
 */
export async function isConditionalUISupported(): Promise<boolean> {
  if (!isPasskeySupported()) return false;
  const Pkc = (globalThis as unknown as { PublicKeyCredential?: { isConditionalMediationAvailable?: () => Promise<boolean> } })
    .PublicKeyCredential;
  if (!Pkc || typeof Pkc.isConditionalMediationAvailable !== 'function') return false;
  try {
    return await Pkc.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

/**
 * Async feature detection: does the device have a built-in platform
 * authenticator (Touch ID, Windows Hello, etc.)?
 *
 * @returns  Promise resolving to `true` iff a platform authenticator is present.
 *
 * @example
 *   const builtIn = await isPlatformAuthenticatorAvailable();
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isPasskeySupported()) return false;
  const Pkc = (globalThis as unknown as { PublicKeyCredential?: { isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean> } })
    .PublicKeyCredential;
  if (!Pkc || typeof Pkc.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') return false;
  try {
    return await Pkc.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
