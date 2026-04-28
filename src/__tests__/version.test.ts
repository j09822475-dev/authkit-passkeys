import { describe, expect, expectTypeOf, it } from 'vitest';
import { version } from '../core/version.js';

describe('version', () => {
  it('should return a semver-shaped string', () => {
    const v = version();
    expect(v).toBeTypeOf('string');
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('should fall back to the source default when no build define is provided', () => {
    expect(version()).toBe('0.1.0');
  });

  it('should expose a () => string signature', () => {
    expectTypeOf(version).toEqualTypeOf<() => string>();
  });
});
