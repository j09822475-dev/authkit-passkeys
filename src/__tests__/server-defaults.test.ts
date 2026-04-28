import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CHALLENGE_BYTES,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_PUB_KEY_CRED_ALG_NAMES,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_USER_VERIFICATION,
  MAX_CHALLENGE_TTL_MS,
  MIN_CHALLENGE_TTL_MS,
} from '../server/defaults.js';

describe('server defaults', () => {
  it('should pin DEFAULT_TIMEOUT_MS to 60_000', () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(60_000);
  });

  it('should pin the challenge TTL window between 30 s and 10 min', () => {
    expect(MIN_CHALLENGE_TTL_MS).toBe(30_000);
    expect(MAX_CHALLENGE_TTL_MS).toBe(600_000);
    expect(DEFAULT_CHALLENGE_TTL_MS).toBeGreaterThanOrEqual(MIN_CHALLENGE_TTL_MS);
    expect(DEFAULT_CHALLENGE_TTL_MS).toBeLessThanOrEqual(MAX_CHALLENGE_TTL_MS);
  });

  it('should pin DEFAULT_CHALLENGE_BYTES to 32', () => {
    expect(DEFAULT_CHALLENGE_BYTES).toBe(32);
  });

  it('should pin DEFAULT_USER_VERIFICATION to required (fintech-friendly default)', () => {
    expect(DEFAULT_USER_VERIFICATION).toBe('required');
  });

  it('should pin DEFAULT_PUB_KEY_CRED_ALG_NAMES to ES256, EdDSA, RS256', () => {
    expect(DEFAULT_PUB_KEY_CRED_ALG_NAMES).toEqual(['ES256', 'EdDSA', 'RS256']);
  });
});
