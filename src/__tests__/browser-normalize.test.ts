import { describe, expect, it } from 'vitest';
import {
  normalizeAuthenticationResponse,
  normalizeRegistrationResponse,
} from '../browser/normalize.js';
import { toBase64Url } from '../core/encoding/base64url.js';
import type { Base64Url } from '../types/webauthn.js';

function strBase64UrlToBuffer(b: Base64Url): ArrayBuffer {
  const padded = (b as string).replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  const s = atob(padded + '='.repeat(padLen));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out.buffer;
}

describe('normalizeRegistrationResponse', () => {
  it('should map every binary field to base64url and include transports / attachment', () => {
    const id = toBase64Url(new Uint8Array([10, 20]));
    const rawId = new Uint8Array([10, 20]).buffer;
    const clientDataJSON = new Uint8Array([1, 2]).buffer;
    const attestationObject = new Uint8Array([3, 4]).buffer;
    const credential = {
      id,
      rawId,
      response: {
        clientDataJSON,
        attestationObject,
        getTransports: () => ['internal', 'hybrid', 'unknown-transport'],
      },
      getClientExtensionResults: () => ({ credProps: { rk: true }, appid: true }),
      authenticatorAttachment: 'platform',
    } as unknown as PublicKeyCredential;
    const out = normalizeRegistrationResponse(credential);
    expect(out.id).toBe(id);
    expect(strBase64UrlToBuffer(out.response.attestationObject).byteLength).toBe(2);
    expect(out.response.transports).toEqual(['internal', 'hybrid']);
    expect(out.authenticatorAttachment).toBe('platform');
    expect(out.clientExtensionResults.appid).toBe(true);
    expect(out.clientExtensionResults.credProps).toEqual({ rk: true });
  });

  it('should omit transports when getTransports returns an empty array', () => {
    const credential = {
      id: 'AAA' as Base64Url,
      rawId: new Uint8Array([0]).buffer,
      response: {
        clientDataJSON: new Uint8Array([0]).buffer,
        attestationObject: new Uint8Array([0]).buffer,
        getTransports: () => [],
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = normalizeRegistrationResponse(credential);
    expect(out.response.transports).toBeUndefined();
  });

  it('should omit transports when getTransports is unavailable', () => {
    const credential = {
      id: 'AAA' as Base64Url,
      rawId: new Uint8Array([0]).buffer,
      response: {
        clientDataJSON: new Uint8Array([0]).buffer,
        attestationObject: new Uint8Array([0]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = normalizeRegistrationResponse(credential);
    expect(out.response.transports).toBeUndefined();
  });

  it('should omit authenticatorAttachment when it is missing', () => {
    const credential = {
      id: 'AAA' as Base64Url,
      rawId: new Uint8Array([0]).buffer,
      response: {
        clientDataJSON: new Uint8Array([0]).buffer,
        attestationObject: new Uint8Array([0]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = normalizeRegistrationResponse(credential);
    expect(out.authenticatorAttachment).toBeUndefined();
  });

  it('should reject an id that is not valid base64url', () => {
    const credential = {
      id: '@@@',
      rawId: new Uint8Array([0]).buffer,
      response: {
        clientDataJSON: new Uint8Array([0]).buffer,
        attestationObject: new Uint8Array([0]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    expect(() => normalizeRegistrationResponse(credential)).toThrow();
  });
});

describe('normalizeAuthenticationResponse', () => {
  it('should map every binary field to base64url and include userHandle / attachment', () => {
    const credential = {
      id: 'AAA' as Base64Url,
      rawId: new Uint8Array([1]).buffer,
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
        userHandle: new Uint8Array([4]).buffer,
      },
      getClientExtensionResults: () => ({ appid: true, appidExclude: false }),
      authenticatorAttachment: 'cross-platform',
    } as unknown as PublicKeyCredential;
    const out = normalizeAuthenticationResponse(credential);
    expect(out.id).toBe('AAA');
    expect(out.response.userHandle).toBeTypeOf('string');
    expect(out.authenticatorAttachment).toBe('cross-platform');
    expect(out.clientExtensionResults.appid).toBe(true);
    expect(out.clientExtensionResults.appidExclude).toBe(false);
  });

  it('should omit userHandle when not provided', () => {
    const credential = {
      id: 'AAA' as Base64Url,
      rawId: new Uint8Array([1]).buffer,
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    const out = normalizeAuthenticationResponse(credential);
    expect(out.response.userHandle).toBeUndefined();
  });

  it('should reject an id that is not valid base64url', () => {
    const credential = {
      id: '@@@',
      rawId: new Uint8Array([1]).buffer,
      response: {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
      },
      getClientExtensionResults: () => ({}),
    } as unknown as PublicKeyCredential;
    expect(() => normalizeAuthenticationResponse(credential)).toThrow();
  });
});
