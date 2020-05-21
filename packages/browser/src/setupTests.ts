// Silence some console output
jest.spyOn(console, 'log').mockImplementation();
jest.spyOn(console, 'debug').mockImplementation();

/**
 * JSDom doesn't seem to support `credentials`, so let's define them here so we can mock their
 * implementations in specific tests.
 */
// @ts-ignore 2540
window.navigator.credentials = {
  // attestation
  create: jest.fn(),
  // assertion
  get: jest.fn(),
};
