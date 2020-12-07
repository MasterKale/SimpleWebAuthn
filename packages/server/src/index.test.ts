import * as index from './index';

test('should export method `generateAttestationOptions`', () => {
  expect(index.generateAttestationOptions).toBeDefined();
});

test('should export method `verifyAttestationResponse`', () => {
  expect(index.verifyAttestationResponse).toBeDefined();
});

test('should export method `generateAssertionOptions`', () => {
  expect(index.generateAssertionOptions).toBeDefined();
});

test('should export method `verifyAssertionResponse`', () => {
  expect(index.verifyAssertionResponse).toBeDefined();
});

test('should export Adapters ', () => {
  expect(index.Adapters.JWTChallengeAdapter).toBeDefined();
  expect(index.Adapters.BaseAdapter).toBeDefined();
});
