import { afterEach, describe, expect, it } from 'vitest';
import {
  isConditionalUISupported,
  isPasskeySupported,
  isPlatformAuthenticatorAvailable,
} from '../browser/feature-detection.js';
import {
  deleteNavigator,
  deletePublicKeyCredential,
  restoreGlobals,
  setNavigator,
  setPublicKeyCredential,
} from './fixtures/dom-globals.js';

afterEach(() => {
  restoreGlobals();
});

describe('isPasskeySupported', () => {
  it('should return false when navigator.credentials is missing', () => {
    setNavigator({});
    setPublicKeyCredential(function () {});
    expect(isPasskeySupported()).toBe(false);
  });

  it('should return false when PublicKeyCredential is missing', () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    deletePublicKeyCredential();
    expect(isPasskeySupported()).toBe(false);
  });

  it('should return true when both APIs are present', () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential(function () {});
    expect(isPasskeySupported()).toBe(true);
  });
});

describe('isConditionalUISupported', () => {
  it('should return false when WebAuthn is not supported', async () => {
    setNavigator({});
    deletePublicKeyCredential();
    expect(await isConditionalUISupported()).toBe(false);
  });

  it('should return false when isConditionalMediationAvailable is missing', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential(function () {});
    expect(await isConditionalUISupported()).toBe(false);
  });

  it('should propagate the result of isConditionalMediationAvailable', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential({ isConditionalMediationAvailable: async () => true });
    expect(await isConditionalUISupported()).toBe(true);
  });

  it('should return false when isConditionalMediationAvailable rejects', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential({
      isConditionalMediationAvailable: async () => {
        throw new Error('boom');
      },
    });
    expect(await isConditionalUISupported()).toBe(false);
  });
});

describe('isPlatformAuthenticatorAvailable', () => {
  it('should return false when WebAuthn is not supported', async () => {
    setNavigator({});
    deletePublicKeyCredential();
    expect(await isPlatformAuthenticatorAvailable()).toBe(false);
  });

  it('should return false when isUserVerifyingPlatformAuthenticatorAvailable is missing', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential(function () {});
    expect(await isPlatformAuthenticatorAvailable()).toBe(false);
  });

  it('should propagate the result of isUserVerifyingPlatformAuthenticatorAvailable', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential({
      isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
    });
    expect(await isPlatformAuthenticatorAvailable()).toBe(true);
  });

  it('should return false when isUserVerifyingPlatformAuthenticatorAvailable rejects', async () => {
    setNavigator({ credentials: { create: () => {}, get: () => {} } });
    setPublicKeyCredential({
      isUserVerifyingPlatformAuthenticatorAvailable: async () => {
        throw new Error('nope');
      },
    });
    expect(await isPlatformAuthenticatorAvailable()).toBe(false);
  });
});
