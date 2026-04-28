/**
 * WebAuthn transport hint. Spec values per WebAuthn Level 3.
 *
 * - `internal` — built-in platform authenticator (Touch ID, Face ID, Windows Hello)
 * - `hybrid`   — cross-device QR-code / caBLE flow (phone-as-authenticator)
 * - `usb`      — USB-attached roaming authenticator (YubiKey, Titan)
 * - `nfc`      — NFC-attached roaming authenticator
 * - `ble`      — Bluetooth-attached roaming authenticator
 */
export type AuthenticatorTransport = 'internal' | 'hybrid' | 'usb' | 'nfc' | 'ble';

export const ALL_TRANSPORTS: readonly AuthenticatorTransport[] = [
  'internal',
  'hybrid',
  'usb',
  'nfc',
  'ble',
];
