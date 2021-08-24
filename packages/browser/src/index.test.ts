import * as index from './index';

test('should export method `startAttestation`', () => {
  expect(index.startAttestation).toBeDefined();
});

test('should export method `startAssertion`', () => {
  expect(index.startAssertion).toBeDefined();
});

test('should export method `browserSupportsWebauthn`', () => {
  expect(index.browserSupportsWebauthn).toBeDefined();
});
