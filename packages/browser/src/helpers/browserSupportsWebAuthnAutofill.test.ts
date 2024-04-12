import { browserSupportsWebAuthnAutofill } from './browserSupportsWebAuthnAutofill';

// Mock "isConditionalMediationAvailable"
const mockICMA = jest.fn();

beforeEach(() => {
  mockICMA.mockReset();

  // @ts-ignore 2741
  window.PublicKeyCredential = jest.fn().mockReturnValue(() => {});
  window.PublicKeyCredential.isConditionalMediationAvailable = mockICMA
    .mockResolvedValue(true);
});

test('should return true when conditional mediation is supported', async () => {
  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  expect(supportsAutofill).toEqual(true);
});

test('should return false when conditional mediation is not supported', async () => {
  mockICMA.mockResolvedValue(false);

  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  expect(supportsAutofill).toEqual(false);
});

test('should return false when browser does not support WebAuthn', async () => {
  // This looks weird but it appeases the linter so it's _fiiiine_
  delete (window as { PublicKeyCredential: unknown }).PublicKeyCredential;
  const supportsAutofill = await browserSupportsWebAuthnAutofill();

  expect(supportsAutofill).toEqual(false);
});
