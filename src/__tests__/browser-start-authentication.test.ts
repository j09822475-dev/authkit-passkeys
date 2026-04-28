import { afterEach, describe, expect, it, vi } from 'vitest';
import { startAuthentication } from '../browser/start-authentication.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import {
  NotSupportedError,
  PasskeyError,
  TimeoutError,
  UserCancelledError,
} from '../errors/index.js';
import type { AuthenticationOptionsJSON, Base64Url } from '../types/webauthn.js';
import {
  deletePublicKeyCredential,
  restoreGlobals,
  setNavigator,
  setPublicKeyCredential,
} from './fixtures/dom-globals.js';

const challenge = new Uint8Array([1, 2, 3]);
const AUTH_JSON: AuthenticationOptionsJSON = {
  challenge: toBase64Url(challenge),
  timeout: 60_000,
  rpId: 'example.com',
  userVerification: 'required',
};

afterEach(() => {
  restoreGlobals();
});

function fakeCredential(): PublicKeyCredential {
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

describe('startAuthentication', () => {
  it('should throw NotSupportedError when WebAuthn is unavailable', async () => {
    setNavigator({});
    deletePublicKeyCredential();
    await expect(startAuthentication(AUTH_JSON)).rejects.toThrow(NotSupportedError);
  });

  it('should throw NotSupportedError when conditional mediation is requested but unavailable', async () => {
    setNavigator({ credentials: { create: () => undefined, get: () => undefined } });
    setPublicKeyCredential(function () {});
    const onFallback = vi.fn();
    await expect(
      startAuthentication(AUTH_JSON, { mediation: 'conditional', onFallback }),
    ).rejects.toThrow(NotSupportedError);
    expect(onFallback).toHaveBeenCalledTimes(1);
  });

  it('should accept conditional mediation when isConditionalMediationAvailable returns true', async () => {
    const get = vi.fn(async (_init: unknown) => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential({ isConditionalMediationAvailable: async () => true });
    const out = await startAuthentication(AUTH_JSON, { mediation: 'conditional' });
    expect(out.type).toBe('public-key');
    expect(
      (get.mock.calls[0]?.[0] as { mediation?: string } | undefined)?.mediation,
    ).toBe('conditional');
  });

  it('should normalise the credential when navigator.credentials.get resolves', async () => {
    const get = vi.fn(async () => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    const out = await startAuthentication(AUTH_JSON);
    expect(out.id).toBeTypeOf('string');
  });

  it('should map NotAllowedError to UserCancelledError when fast', async () => {
    const get = vi.fn(async () => {
      const e = new Error('cancel');
      e.name = 'NotAllowedError';
      throw e;
    });
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    await expect(startAuthentication(AUTH_JSON)).rejects.toThrow(UserCancelledError);
  });

  it('should call onFallback with the mapped error before rethrowing', async () => {
    const onFallback = vi.fn();
    const get = vi.fn(async () => {
      const e = new Error('boom');
      e.name = 'AbortError';
      throw e;
    });
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    await expect(startAuthentication(AUTH_JSON, { onFallback })).rejects.toThrow(
      UserCancelledError,
    );
    expect(onFallback).toHaveBeenCalledTimes(1);
    expect(onFallback.mock.calls[0]?.[0]).toBeInstanceOf(PasskeyError);
  });

  it('should throw NotSupportedError when navigator.credentials.get resolves to null', async () => {
    const get = vi.fn(async () => null);
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    await expect(startAuthentication(AUTH_JSON)).rejects.toThrow(NotSupportedError);
  });

  it('should map a long-running NotAllowedError to TimeoutError', async () => {
    const realNow = Date.now;
    let calls = 0;
    Date.now = () => (calls++ === 0 ? 0 : 60_000);
    try {
      const get = vi.fn(async () => {
        const e = new Error('timed out');
        e.name = 'NotAllowedError';
        throw e;
      });
      setNavigator({ credentials: { create: () => undefined, get } });
      setPublicKeyCredential(function () {});
      await expect(startAuthentication(AUTH_JSON)).rejects.toThrow(TimeoutError);
    } finally {
      Date.now = realNow;
    }
  });

  it('should pass the AbortSignal through to navigator.credentials.get', async () => {
    const get = vi.fn(async (_init: unknown) => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    const ctrl = new AbortController();
    await startAuthentication(AUTH_JSON, { signal: ctrl.signal });
    expect(
      (get.mock.calls[0]?.[0] as { signal?: AbortSignal } | undefined)?.signal,
    ).toBe(ctrl.signal);
  });

  it('should preserve allowCredentials with proper base64url decoding', async () => {
    const get = vi.fn(async (_init: unknown) => fakeCredential());
    setNavigator({ credentials: { create: () => undefined, get } });
    setPublicKeyCredential(function () {});
    const opts: AuthenticationOptionsJSON = {
      ...AUTH_JSON,
      allowCredentials: [
        {
          id: toBase64Url(new Uint8Array([42])) as Base64Url,
          type: 'public-key',
          transports: ['internal'],
        },
      ],
    };
    await startAuthentication(opts);
    const call = get.mock.calls[0]?.[0] as
      | { publicKey?: { allowCredentials?: unknown[] } }
      | undefined;
    expect(call?.publicKey?.allowCredentials).toHaveLength(1);
  });
});
