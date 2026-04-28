export { startRegistration, type RegisterInit } from './start-registration.js';
export { startAuthentication, type AuthenticateInit } from './start-authentication.js';
export { startConditionalUI, type ConditionalUIHandle } from './conditional-ui.js';
export {
  isConditionalUISupported,
  isPasskeySupported,
  isPlatformAuthenticatorAvailable,
} from './feature-detection.js';
export {
  parseAuthenticationOptions,
  parseRegistrationOptions,
} from './parse-options.js';
