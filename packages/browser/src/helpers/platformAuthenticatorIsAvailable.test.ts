import { platformAuthenticatorIsAvailable } from './platformAuthenticatorIsAvailable';

const mockIsUVPAA = jest.fn();

beforeEach(() => {
  mockIsUVPAA.mockReset();

  // @ts-ignore 2741
  window.PublicKeyCredential = jest.fn().mockReturnValue(() => {});
  window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
    mockIsUVPAA.mockResolvedValue(true);
});

test('should return true when platform authenticator is available', async () => {
  const isAvailable = await platformAuthenticatorIsAvailable();

  expect(isAvailable).toEqual(true);
});

test('should return false when platform authenticator is unavailable', async () => {
  mockIsUVPAA.mockResolvedValue(false);

  const isAvailable = await platformAuthenticatorIsAvailable();

  expect(isAvailable).toEqual(false);
});

test('should return false when browser does not support WebAuthn', async () => {
  delete (window as any).PublicKeyCredential;
  const isAvailable = await platformAuthenticatorIsAvailable();

  expect(isAvailable).toEqual(false);
});
