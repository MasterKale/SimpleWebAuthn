import supportsWebauthn from './supportsWebauthn';

beforeEach(() => {
  // @ts-ignore 2741
  window.PublicKeyCredential = jest.fn().mockReturnValue(() => {});
});

test('should return true when browser supports WebAuthn', () => {
  expect(supportsWebauthn()).toBe(true);
});

test('should return false when browser does not support WebAuthn', () => {
  delete window.PublicKeyCredential;
  expect(supportsWebauthn()).toBe(false);
});
