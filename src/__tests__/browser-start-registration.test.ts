import { afterEach, describe, expect, it, vi } from 'vitest';
import { startRegistration } from '../browser/start-registration.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import {
  NotSupportedError,
  PasskeyError,
  TimeoutError,
  UserCancelledError,
} from '../errors/index.js';
import type { RegistrationOptionsJSON } from '../types/webauthn.js';
import {
  deletePublicKeyCredential,
  restoreGlobals,
  setNavigator,
  setPublicKeyCredential,
} from './fixtures/dom-globals.js';

const userIdBytes = new TextEncoder().encode('u');
const challenge = new Uint8Array([1, 2, 3]);

const REG_JSON: RegistrationOptionsJSON = {
  rp: { id: 'example.com', name: 'Example' },
  user: { id: toBase64Url(userIdBytes), name: 'a', displayName: 'b' },
  challenge: toBase64Url(challenge),
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  timeout: 60_000,
};

afterEach(() => {
  restoreGlobals();
});

function fakeCredential(): PublicKeyCredential {
  return {
    id: toBase64Url(new Uint8Array([7])),
    rawId: new Uint8Array([7]).buffer,
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      attestationObject: new Uint8Array([2]).buffer,
      getTransports: () => ['internal'],
    },
    getClientExtensionResults: () => ({}),
    authenticatorAttachment: 'platform',
    type: 'public-key',
  } as unknown as PublicKeyCredential;
}

describe('startRegistration', () => {
  it('should throw NotSupportedError when WebAuthn is not available', async () => {
    setNavigator({});
    deletePublicKeyCredential();
    await expect(startRegistration(REG_JSON)).rejects.toThrow(NotSupportedError);
  });

  it('should call onFallback before throwing NotSupportedError', async () => {
    setNavigator({});
    deletePublicKeyCredential();
    const onFallback = vi.fn();
    await expect(startRegistration(REG_JSON, { onFallback })).rejects.toThrow(NotSupportedError);
    expect(onFallback).toHaveBeenCalledTimes(1);
    expect(onFallback.mock.calls[0]?.[0]).toBeInstanceOf(NotSupportedError);
  });

  it('should normalise the credential when navigator.credentials.create resolves', async () => {
    const create = vi.fn(async () => fakeCredential());
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    const out = await startRegistration(REG_JSON);
    expect(out.id).toBeTypeOf('string');
    expect(out.type).toBe('public-key');
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('should pass the AbortSignal through to navigator.credentials.create', async () => {
    const create = vi.fn(async (_init: unknown) => fakeCredential());
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    const ctrl = new AbortController();
    await startRegistration(REG_JSON, { signal: ctrl.signal });
    expect(
      (create.mock.calls[0]?.[0] as { signal?: AbortSignal } | undefined)?.signal,
    ).toBe(ctrl.signal);
  });

  it('should map a NotAllowedError to UserCancelledError when fast', async () => {
    const create = vi.fn(async () => {
      const e = new Error('user denied');
      e.name = 'NotAllowedError';
      throw e;
    });
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    await expect(startRegistration(REG_JSON)).rejects.toThrow(UserCancelledError);
  });

  it('should call onFallback with the mapped error before rethrowing', async () => {
    const onFallback = vi.fn();
    const create = vi.fn(async () => {
      const e = new Error('cancelled');
      e.name = 'AbortError';
      throw e;
    });
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    await expect(startRegistration(REG_JSON, { onFallback })).rejects.toThrow(UserCancelledError);
    expect(onFallback).toHaveBeenCalledTimes(1);
    expect(onFallback.mock.calls[0]?.[0]).toBeInstanceOf(PasskeyError);
  });

  it('should map a long-running NotAllowedError to TimeoutError', async () => {
    const realNow = Date.now;
    let calls = 0;
    Date.now = () => (calls++ === 0 ? 0 : 60_000);
    try {
      const create = vi.fn(async () => {
        const e = new Error('timed out');
        e.name = 'NotAllowedError';
        throw e;
      });
      setNavigator({ credentials: { create, get: () => undefined } });
      setPublicKeyCredential(function () {});
      await expect(startRegistration(REG_JSON)).rejects.toThrow(TimeoutError);
    } finally {
      Date.now = realNow;
    }
  });

  it('should throw NotSupportedError when navigator.credentials.create returns null', async () => {
    const create = vi.fn(async () => null);
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    await expect(startRegistration(REG_JSON)).rejects.toThrow(NotSupportedError);
  });

  it('should call onFallback when navigator.credentials.create returns null', async () => {
    const create = vi.fn(async () => null);
    const onFallback = vi.fn();
    setNavigator({ credentials: { create, get: () => undefined } });
    setPublicKeyCredential(function () {});
    await expect(startRegistration(REG_JSON, { onFallback })).rejects.toThrow(NotSupportedError);
    expect(onFallback).toHaveBeenCalledTimes(1);
  });
});
