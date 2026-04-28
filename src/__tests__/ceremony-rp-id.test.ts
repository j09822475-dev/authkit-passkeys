import { describe, expect, it } from 'vitest';
import {
  assertOriginMatchesRpId,
  deriveRpIdFromOrigin,
} from '../core/ceremony/rp-id.js';
import { InvalidOriginError, InvalidRpIdError } from '../errors/index.js';

describe('assertOriginMatchesRpId', () => {
  it('should accept an https origin whose host equals the rpId', () => {
    expect(() => assertOriginMatchesRpId('https://example.com', 'example.com')).not.toThrow();
  });

  it('should accept an https subdomain of the rpId', () => {
    expect(() => assertOriginMatchesRpId('https://app.example.com', 'example.com')).not.toThrow();
  });

  it('should accept http://localhost for development', () => {
    expect(() => assertOriginMatchesRpId('http://localhost:3000', 'localhost')).not.toThrow();
    expect(() => assertOriginMatchesRpId('http://127.0.0.1', '127.0.0.1')).not.toThrow();
  });

  it('should throw InvalidOriginError on a malformed URL', () => {
    expect(() => assertOriginMatchesRpId('not-a-url', 'example.com')).toThrow(InvalidOriginError);
  });

  it('should throw InvalidOriginError on a non-https scheme outside localhost', () => {
    expect(() => assertOriginMatchesRpId('http://example.com', 'example.com')).toThrow(
      InvalidOriginError,
    );
  });

  it('should throw InvalidRpIdError when the host is unrelated to rpId', () => {
    expect(() => assertOriginMatchesRpId('https://evil.com', 'example.com')).toThrow(
      InvalidRpIdError,
    );
  });

  it('should reject a host that is a suffix but not a subdomain (e.g. fooexample.com vs example.com)', () => {
    expect(() => assertOriginMatchesRpId('https://fooexample.com', 'example.com')).toThrow(
      InvalidRpIdError,
    );
  });
});

describe('deriveRpIdFromOrigin', () => {
  it('should return the hostname of an https origin', () => {
    expect(deriveRpIdFromOrigin('https://app.example.com')).toBe('app.example.com');
  });

  it('should return localhost as-is', () => {
    expect(deriveRpIdFromOrigin('http://localhost:3000')).toBe('localhost');
  });

  it('should strip IPv6 brackets', () => {
    expect(deriveRpIdFromOrigin('http://[::1]:3000')).toBe('::1');
  });
});
