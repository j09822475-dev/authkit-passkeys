import { PasskeyError } from '../../errors/base.js';

/**
 * Decoded CBOR value. The library only emits the subset relevant to WebAuthn:
 * unsigned/negative integers, byte strings, text strings, arrays, maps,
 * tagged values, booleans, null/undefined, and floats.
 */
export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | undefined
  | CborValue[]
  | Map<CborValue, CborValue>
  | { tag: number; value: CborValue };

interface CursorState {
  readonly view: DataView;
  readonly bytes: Uint8Array;
  offset: number;
}

const MAJOR_UINT = 0;
const MAJOR_NINT = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;

/**
 * Decode-only CBOR parser covering the subset needed for WebAuthn (COSE keys
 * and attestation objects). Hand-written to keep the bundle ~1 KB.
 *
 * @param input  CBOR-encoded bytes.
 * @returns      `{ value, bytesRead }` — `bytesRead` lets callers split off trailing data.
 * @throws {PasskeyError}  Code `'invalid_attestation'` for any malformed input.
 *
 * @example
 *   const { value: attObj, bytesRead } = decodeCbor(attestationBytes);
 */
export function decodeCbor(input: Uint8Array): { value: CborValue; bytesRead: number } {
  const state: CursorState = {
    view: new DataView(input.buffer, input.byteOffset, input.byteLength),
    bytes: input,
    offset: 0,
  };
  const value = decodeItem(state);
  return { value, bytesRead: state.offset };
}

function decodeItem(state: CursorState): CborValue {
  if (state.offset >= state.bytes.length) {
    throw bad('CBOR truncated.');
  }
  const initialByte = state.bytes[state.offset++] as number;
  const major = initialByte >> 5;
  const minor = initialByte & 0x1f;

  if (major === MAJOR_SIMPLE) {
    return decodeSimple(state, minor);
  }

  const length = readLength(state, minor);

  switch (major) {
    case MAJOR_UINT:
      return length;
    case MAJOR_NINT:
      return typeof length === 'bigint' ? -1n - length : -1 - (length as number);
    case MAJOR_BYTES: {
      const len = toNumber(length);
      const slice = state.bytes.subarray(state.offset, state.offset + len);
      state.offset += len;
      return slice.slice();
    }
    case MAJOR_TEXT: {
      const len = toNumber(length);
      const slice = state.bytes.subarray(state.offset, state.offset + len);
      state.offset += len;
      return new TextDecoder('utf-8', { fatal: true }).decode(slice);
    }
    case MAJOR_ARRAY: {
      const len = toNumber(length);
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) arr.push(decodeItem(state));
      return arr;
    }
    case MAJOR_MAP: {
      const len = toNumber(length);
      const map = new Map<CborValue, CborValue>();
      for (let i = 0; i < len; i++) {
        const k = decodeItem(state);
        const v = decodeItem(state);
        map.set(k, v);
      }
      return map;
    }
    case MAJOR_TAG:
      return { tag: toNumber(length), value: decodeItem(state) };
    default:
      throw bad(`Unsupported CBOR major type ${major}.`);
  }
}

function readLength(state: CursorState, minor: number): number | bigint {
  if (minor < 24) return minor;
  switch (minor) {
    case 24:
      return state.bytes[state.offset++] as number;
    case 25: {
      const n = state.view.getUint16(state.offset);
      state.offset += 2;
      return n;
    }
    case 26: {
      const n = state.view.getUint32(state.offset);
      state.offset += 4;
      return n;
    }
    case 27: {
      const hi = state.view.getUint32(state.offset);
      const lo = state.view.getUint32(state.offset + 4);
      state.offset += 8;
      const n = (BigInt(hi) << 32n) | BigInt(lo);
      return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
    }
    default:
      throw bad(`Unsupported CBOR length encoding ${minor}.`);
  }
}

function decodeSimple(state: CursorState, minor: number): CborValue {
  switch (minor) {
    case 20:
      return false;
    case 21:
      return true;
    case 22:
      return null;
    case 23:
      return undefined;
    case 25: {
      const n = state.view.getUint16(state.offset);
      state.offset += 2;
      return decodeFloat16(n);
    }
    case 26: {
      const n = state.view.getFloat32(state.offset);
      state.offset += 4;
      return n;
    }
    case 27: {
      const n = state.view.getFloat64(state.offset);
      state.offset += 8;
      return n;
    }
    default:
      throw bad(`Unsupported CBOR simple value ${minor}.`);
  }
}

function decodeFloat16(half: number): number {
  const sign = (half & 0x8000) >> 15;
  const exp = (half & 0x7c00) >> 10;
  const frac = half & 0x03ff;
  let value: number;
  if (exp === 0) value = frac === 0 ? 0 : Math.pow(2, -14) * (frac / 1024);
  else if (exp === 31) value = frac === 0 ? Infinity : NaN;
  else value = Math.pow(2, exp - 15) * (1 + frac / 1024);
  return sign === 0 ? value : -value;
}

function toNumber(n: number | bigint): number {
  if (typeof n === 'number') return n;
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw bad('CBOR length exceeds Number.MAX_SAFE_INTEGER.');
  }
  return Number(n);
}

function bad(msg: string): PasskeyError {
  return new PasskeyError('invalid_attestation', msg, {
    details: { reason: 'attestation_statement_invalid' },
  });
}
