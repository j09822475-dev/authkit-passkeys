import { describe, expect, it } from 'vitest';
import {
  ANONYMOUS_AAGUID,
  aaguidToUuid,
  fromHex,
  toHex,
  uuidToAaguid,
} from '../core/encoding/hex.js';
import { InternalError } from '../errors/index.js';

describe('toHex', () => {
  it('should encode bytes as a lowercase hex string', () => {
    expect(toHex(new Uint8Array([0xab, 0x01, 0x00, 0xff]))).toBe('ab0100ff');
  });

  it('should return an empty string for empty input', () => {
    expect(toHex(new Uint8Array(0))).toBe('');
  });

  it('should pad single-digit values to two chars', () => {
    expect(toHex(new Uint8Array([0x0a]))).toBe('0a');
  });
});

describe('fromHex', () => {
  it('should decode a plain hex string', () => {
    expect(Array.from(fromHex('ab0100ff'))).toEqual([0xab, 0x01, 0x00, 0xff]);
  });

  it('should accept a 0x prefix', () => {
    expect(Array.from(fromHex('0xab01'))).toEqual([0xab, 0x01]);
  });

  it('should accept upper-case hex', () => {
    expect(Array.from(fromHex('AB01'))).toEqual([0xab, 0x01]);
  });

  it('should throw InternalError on odd length input', () => {
    expect(() => fromHex('abc')).toThrow(InternalError);
  });

  it('should throw InternalError on non-hex characters', () => {
    expect(() => fromHex('zz01')).toThrow(InternalError);
  });
});

describe('aaguidToUuid', () => {
  it('should format 16 bytes as a canonical UUID string', () => {
    const bytes = new Uint8Array([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    expect(aaguidToUuid(bytes)).toBe('00112233-4455-6677-8899-aabbccddeeff');
  });

  it('should throw InternalError when input is not exactly 16 bytes', () => {
    expect(() => aaguidToUuid(new Uint8Array(15))).toThrow(InternalError);
    expect(() => aaguidToUuid(new Uint8Array(17))).toThrow(InternalError);
  });
});

describe('uuidToAaguid', () => {
  it('should round-trip through aaguidToUuid', () => {
    const bytes = new Uint8Array(16);
    bytes[0] = 0xab;
    bytes[15] = 0xcd;
    const uuid = aaguidToUuid(bytes);
    expect(Array.from(uuidToAaguid(uuid))).toEqual(Array.from(bytes));
  });

  it('should accept upper-case input', () => {
    expect(Array.from(uuidToAaguid('00112233-4455-6677-8899-AABBCCDDEEFF'))).toEqual([
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
  });

  it('should throw InternalError for malformed UUIDs', () => {
    expect(() => uuidToAaguid('not-a-uuid')).toThrow(InternalError);
    expect(() => uuidToAaguid('00112233')).toThrow(InternalError);
  });
});

describe('ANONYMOUS_AAGUID', () => {
  it('should equal the all-zeros UUID', () => {
    expect(ANONYMOUS_AAGUID).toBe('00000000-0000-0000-0000-000000000000');
  });

  it('should equate to aaguidToUuid(<16 zero bytes>)', () => {
    expect(aaguidToUuid(new Uint8Array(16))).toBe(ANONYMOUS_AAGUID);
  });
});
