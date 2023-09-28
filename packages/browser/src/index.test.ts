import * as index from './index';

test('should export method `startRegistration`', () => {
  expect(index.startRegistration).toBeDefined();
});

test('should export method `startAuthentication`', () => {
  expect(index.startAuthentication).toBeDefined();
});

test('should export method `browserSupportsWebAuthn`', () => {
  expect(index.browserSupportsWebAuthn).toBeDefined();
});

test('should export method `browserSupportsWebAuthnAutofill`', () => {
  expect(index.browserSupportsWebAuthnAutofill).toBeDefined();
});

test('should export method `platformAuthenticatorIsAvailable`', () => {
  expect(index.platformAuthenticatorIsAvailable).toBeDefined();
});

test('should export method `base64URLStringToBuffer`', () => {
  expect(index.base64URLStringToBuffer).toBeDefined();
});

test('should export method `bufferToBase64URLString`', () => {
  expect(index.bufferToBase64URLString).toBeDefined();
});
