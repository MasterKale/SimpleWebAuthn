import * as index from './index';

test('should export method `startRegistration`', () => {
  expect(index.startRegistration).toBeDefined();
});

test('should export method `startAuthentication`', () => {
  expect(index.startAuthentication).toBeDefined();
});

test('should export method `browserSupportsWebauthn`', () => {
  expect(index.browserSupportsWebauthn).toBeDefined();
});

test('should export method `platformAuthenticatorIsAvailable`', () => {
  expect(index.browserSupportsWebauthn).toBeDefined();
});
