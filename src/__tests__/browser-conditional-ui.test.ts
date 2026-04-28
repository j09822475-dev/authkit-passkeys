import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { startConditionalUI } from '../browser/conditional-ui.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import { UserCancelledError } from '../errors/index.js';
import type { AuthenticationOptionsJSON } from '../types/webauthn.js';
import {
  restoreGlobals,
  setNavigator,
  setPublicKeyCredential,
} from './fixtures/dom-globals.js';

const AUTH_JSON: AuthenticationOptionsJSON = {
  challenge: toBase64Url(new Uint8Array([1, 2])),
  rpId: 'example.com',
};

beforeEach(() => {
  setPublicKeyCredential({ isConditionalMediationAvailable: async () => true });
});

afterEach(() => {
  restoreGlobals();
});

function fakeCredential() {
  return {
    id: toBase64Url(new Uint8Array([1])),
    rawId: new Uint8Array([1]).buffer,
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
    },
    getClientExtensionResults: () => ({}),
    type: 'public-key',
  } as unknown as PublicKeyCredential;
}

describe('startConditionalUI', () => {
  it('should bundle a result promise and a cancel function', async () => {
    const get = vi.fn(async () => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    const handle = startConditionalUI(AUTH_JSON);
    const result = await handle.result;
    expect(result.type).toBe('public-key');
    expect(typeof handle.cancel).toBe('function');
  });

  it('should pass mediation: conditional and a fresh AbortSignal to startAuthentication', async () => {
    const get = vi.fn(async (_init: unknown) => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    const handle = startConditionalUI(AUTH_JSON);
    await handle.result;
    const call = get.mock.calls[0]?.[0] as
      | { mediation?: string; signal?: AbortSignal }
      | undefined;
    expect(call?.mediation).toBe('conditional');
    expect(call?.signal).toBeInstanceOf(AbortSignal);
  });

  it('should abort the in-flight ceremony when cancel() is invoked', async () => {
    let receivedSignal: AbortSignal | undefined;
    const get = vi.fn(async (init: { signal?: AbortSignal }) => {
      receivedSignal = init.signal;
      return new Promise<PublicKeyCredential | null>((_resolve, reject) => {
        const onAbort = (): void => {
          const e = new Error('aborted');
          e.name = 'AbortError';
          reject(e);
        };
        if (init.signal?.aborted) onAbort();
        else init.signal?.addEventListener('abort', onAbort);
      });
    });
    setNavigator({ credentials: { create: () => undefined, get } });
    const handle = startConditionalUI(AUTH_JSON);
    // Wait one microtask so the inner startAuthentication reaches navigator.credentials.get.
    await Promise.resolve();
    await Promise.resolve();
    handle.cancel();
    await expect(handle.result).rejects.toThrow(UserCancelledError);
    expect(receivedSignal?.aborted).toBe(true);
  });
});
