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

test('should return false when window is undefined', () => {
  // Make window undefined as it is in node environments.
  const windowSpy = jest.spyOn<any, 'window'>(global, 'window', 'get');
  windowSpy.mockImplementation(() => undefined);

  expect(window).toBe(undefined);
  expect(supportsWebauthn()).toBe(false);

  // Restore original window value.
  windowSpy.mockRestore();
});
